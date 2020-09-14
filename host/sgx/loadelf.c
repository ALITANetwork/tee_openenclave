// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/properties.h>
#include <openenclave/internal/queue.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <stdlib.h>
#include <string.h>
#include "../memalign.h"
#include "../strings.h"
#include "enclave.h"
#include "sgxload.h"

/* Forward declarations */
static oe_result_t _load_elf_image(
    const char* path,
    oe_enclave_elf_image_t* image);

oe_result_t _load_needed_images(
    const char* path,
    size_t path_length,
    oe_enclave_elf_image_t* image);

typedef struct _needed_image_entry
{
    OE_SLIST_ENTRY(_needed_image_entry) next;
    const char* name;
} needed_image_entry_t;

static void _unload_elf_image(oe_enclave_elf_image_t* image)
{
    if (image)
    {
        for (size_t i = 0; i < image->num_needed_images; i++)
        {
            _unload_elf_image(&image->needed_images[i]);
        }

        if (image->needed_images)
            free(image->needed_images);

        if (image->elf.data)
            free(image->elf.data);

        if (image->image_base)
            oe_memalign_free(image->image_base);

        if (image->segments)
            oe_memalign_free(image->segments);

        if (image->reloc_data)
            oe_memalign_free(image->reloc_data);
    }
}

static oe_result_t _unload_image(oe_enclave_image_t* image)
{
    if (image)
    {
        _unload_elf_image(&image->elf);
        memset(image, 0, sizeof(*image));
    }
    return OE_OK;
}

/* Loads an ELF64 binary from disk into memory as image->elf.data
 * and provides a pointer to it as an ELF64 header structure.
 *
 * The caller is responsible for calling free on image->elf.data.
 */
static oe_result_t _read_elf_header(
    const char* path,
    oe_enclave_elf_image_t* image,
    elf64_ehdr_t** ehdr)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_ehdr_t* eh = NULL;

    /* Load the ELF64 into memory */
    if (elf64_load(path, &image->elf) != 0)
    {
        OE_RAISE(OE_INVALID_IMAGE);
    }
    eh = (elf64_ehdr_t*)image->elf.data;

    /* Fail if not PIE or shared object */
    if (eh->e_type != ET_DYN)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "ELF image is not a PIE or shared object", NULL);

    /* Fail if not Intel X86 64-bit */
    if (eh->e_machine != EM_X86_64)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "ELF image is not Intel X86 64-bit", NULL);

    /* Save entry point address needed to be set in the TCS for enclave app */
    image->entry_rva = eh->e_entry;

    *ehdr = eh;
    result = OE_OK;

done:
    return result;
}

/* Scan through the section headers to populate the following properties in the
 * image->elf struct:
 *   .oeinfo: oeinfo_rva, oeinfo_file_pos
 *   .tdata: tdata_rva, tdata_size, tdata_align
 *   .tbss: tbss_size, tbss_align
 *
 * Also checks for the presence of the .note.gnu.build-id which is needed for
 * the debugger contract.
 */
static oe_result_t _read_sections(
    const elf64_ehdr_t* ehdr,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    bool has_build_id = false;

    for (size_t i = 0; i < ehdr->e_shnum; i++)
    {
        const elf64_shdr_t* sh = elf64_get_section_header(&image->elf, i);

        /* Invalid section header. The elf file is corrupted. */
        if (sh == NULL)
            OE_RAISE(OE_INVALID_IMAGE);

        const char* name =
            elf64_get_string_from_shstrtab(&image->elf, sh->sh_name);

        if (name)
        {
            if (strcmp(name, ".oeinfo") == 0)
            {
                image->oeinfo_rva = sh->sh_addr;
                image->oeinfo_file_pos = sh->sh_offset;
                OE_TRACE_VERBOSE(
                    "Found properties block offset %lx size %lx",
                    sh->sh_offset,
                    sh->sh_size);
            }
            else if (strcmp(name, ".note.gnu.build-id") == 0)
            {
                has_build_id = true;
            }
            else if (strcmp(name, ".tdata") == 0)
            {
                // These items must match program header values.
                image->tdata_rva = sh->sh_addr;
                image->tdata_size = sh->sh_size;
                image->tdata_align = sh->sh_addralign;

                OE_TRACE_VERBOSE(
                    "tdata { rva=%lx, size=%lx, align=%ld }",
                    sh->sh_addr,
                    sh->sh_size,
                    sh->sh_addralign);
            }
            else if (strcmp(name, ".tbss") == 0)
            {
                image->tbss_size = sh->sh_size;
                image->tbss_align = sh->sh_addralign;
                OE_TRACE_VERBOSE(
                    "tbss { size=%ld, align=%ld }",
                    sh->sh_size,
                    sh->sh_addralign);
            }
        }
    }

    /* It is now the default for linux shared libraries and executables to
     * have the build-id note. GCC by default passes the --build-id option
     * to linker, whereas clang does not. Build-id is also used as a key by
     * debug symbol-servers. If no build-id is found emit a trace message.
     * */
    if (!has_build_id)
    {
        OE_TRACE_ERROR("Enclave image does not have build-id.");
    }

    result = OE_OK;

done:
    return result;
}

/* Reads the number of loadable segments and allocates a zeroed, page-aligned
 * image buffer for reading the segment contents into.
 *
 * The caller is responsible for calling memalign_free on image->image_base.
 */
static oe_result_t _initialize_image_segments(
    const elf64_ehdr_t* ehdr,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Find out the image size and number of segments to be loaded */
    uint64_t lo = 0xFFFFFFFFFFFFFFFF; /* lowest address of all segments */
    uint64_t hi = 0;                  /* highest address of all segments */

    for (size_t i = 0; i < ehdr->e_phnum; i++)
    {
        const elf64_phdr_t* ph = elf64_get_program_header(&image->elf, i);

        /* Check for corrupted program header. */
        if (ph == NULL)
            OE_RAISE(OE_INVALID_IMAGE);

        /* Check for proper sizes for the program segment. */
        if (ph->p_filesz > ph->p_memsz)
            OE_RAISE(OE_INVALID_IMAGE);

        switch (ph->p_type)
        {
            case PT_LOAD:
                if (lo > ph->p_vaddr)
                    lo = ph->p_vaddr;

                if (hi < ph->p_vaddr + ph->p_memsz)
                    hi = ph->p_vaddr + ph->p_memsz;

                image->num_segments++;
                break;

            default:
                break;
        }
    }

    /* Fail if LO not found */
    if (lo != 0)
        OE_RAISE(OE_INVALID_IMAGE);

    /* Fail if HI not found */
    if (hi == 0)
        OE_RAISE(OE_INVALID_IMAGE);

    /* Fail if no segment found */
    if (image->num_segments == 0)
        OE_RAISE(OE_INVALID_IMAGE);

    /* Calculate the full size of the image (rounded up to the page size) */
    image->image_size = oe_round_up_to_page_size(hi - lo);

    /* Allocate the in-memory image for program segments on a page boundary */
    image->image_base = (char*)oe_memalign(OE_PAGE_SIZE, image->image_size);
    if (!image->image_base)
    {
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    /* Zero initialize the in-memory image */
    memset(image->image_base, 0, image->image_size);

    result = OE_OK;

done:
    return result;
}

/* Populates the image buffer with the contents of all loadable segments.
 * For each loaded segment, this function caches the segment properties
 * needed during enclave load in image->segments.
 *
 * Also validates that the PT_TLS segment conforms to the enclave loader
 * expectations for handling TLS.
 *
 * The caller is responsible for calling memalign_free on image->segments.
 */
static oe_result_t _stage_image_segments(
    const elf64_ehdr_t* ehdr,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Allocate array of cached segment structures for enclave load */
    size_t segments_size = image->num_segments * sizeof(oe_elf_segment_t);
    image->segments =
        (oe_elf_segment_t*)oe_memalign(OE_PAGE_SIZE, segments_size);
    memset(image->segments, 0, segments_size);
    if (!image->segments)
    {
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    /* Read all loadable program segments into in-memory image and cache their
     * properties in the segments array. */
    for (size_t i = 0, pt_read_segments_index = 0; i < ehdr->e_phnum; i++)
    {
        const elf64_phdr_t* ph = elf64_get_program_header(&image->elf, i);
        oe_elf_segment_t* segment = &image->segments[pt_read_segments_index];

        assert(ph);
        assert(ph->p_filesz <= ph->p_memsz);

        switch (ph->p_type)
        {
            case PT_LOAD:
            {
                /* Cache the segment properties for enclave page add */
                segment->memsz = ph->p_memsz;
                segment->vaddr = ph->p_vaddr;
                segment->flags = ph->p_flags;

                void* segment_data = elf64_get_segment(&image->elf, i);
                if (!segment_data)
                {
                    OE_RAISE_MSG(
                        OE_INVALID_IMAGE,
                        "Failed to get segment at index %lu",
                        i);
                }

                /* Copy the segment data to the image buffer */
                memcpy(
                    image->image_base + segment->vaddr,
                    segment_data,
                    ph->p_filesz);
                pt_read_segments_index++;
                break;
            }
            case PT_TLS:
            {
                // The ELF Handling for ELF Storage spec
                // (https://uclibc.org/docs/tls.pdf) says in page 4:
                //     "The section header is not usable; instead a new program
                //      header entry is created."
                // These assertions exist to understand those scenarios better.
                // Currently, in all cases except one, the section and program
                // header values are observed to be same.
                if (image->tdata_rva != ph->p_vaddr)
                {
                    if (image->tdata_rva == 0)
                    {
                        // The ELF has no thread local variables that are
                        // explicitly initialized. Therefore there is no .tdata
                        // section; only a .tbss section.
                        //
                        // In this case, the linker seems to put the address of
                        // the .tbss section in p_vaddr field; however it leaves
                        // the size zero. This seems to be strange linker
                        // behavior; we don't assert on it.
                        OE_TRACE_INFO(
                            "Ignoring .tdata_rva, p_vaddr mismatch for "
                            "empty .tdata section");
                    }
                    else
                    {
                        OE_RAISE_MSG(
                            OE_INVALID_IMAGE,
                            ".tdata rva mismatch. Section value = "
                            "%lx, Program header value = 0x%lx",
                            image->tdata_rva,
                            ph->p_vaddr);
                    }
                }
                if (image->tdata_size != ph->p_filesz)
                {
                    // Always assert on size mismatch.
                    OE_RAISE_MSG(
                        OE_INVALID_IMAGE,
                        ".tdata_size mismatch. Section value = %lx, "
                        "Program header value = 0x%lx",
                        image->tdata_size,
                        ph->p_filesz);
                }
                break;
            }
            default:
                /* Ignore all other segment types */
                break;
        }
    }

    /* Check that segments are valid */
    for (size_t i = 0; i < image->num_segments - 1; i++)
    {
        const oe_elf_segment_t* current = &image->segments[i];
        const oe_elf_segment_t* next = &image->segments[i + 1];
        if (current->vaddr >= next->vaddr)
        {
            OE_RAISE_MSG(
                OE_UNEXPECTED, "Segment vaddrs found out of order", NULL);
        }
        if ((current->vaddr + current->memsz) >
            oe_round_down_to_page_size(next->vaddr))
        {
            OE_RAISE_MSG(OE_INVALID_IMAGE, "Overlapping segments found", NULL);
        }
    }

    result = OE_OK;

done:
    return result;
}

OE_INLINE void _dump_relocations(const void* data, size_t size)
{
    const elf64_rela_t* p = (const elf64_rela_t*)data;
    size_t n = size / sizeof(elf64_rela_t);

    printf("=== Relocations:\n");

    for (size_t i = 0; i < n; i++, p++)
    {
        if (p->r_offset == 0)
            break;

        printf(
            "offset=%llu addend=%lld\n",
            OE_LLU(p->r_offset),
            OE_LLD(p->r_addend));
    }
}

/* Recursively load all needed dependencies of the specified image by parsing
 * the DT_NEEDED entries in the .dynamic section. The needed enclave images are
 * resolved only to the same folder as the parent ELF and ignores standard
 * search paths and DT_RPATH/DT_RUNPATH settings.
 */
oe_result_t _load_needed_images(
    const char* path,
    size_t path_length,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    const elf64_dyn_t* dyn;
    size_t dyn_count = 0;
    char* needed_image_path = NULL;
    OE_SLIST_HEAD(needed_image_list_head_t, _needed_image_entry)
    needed_image_list_head;

    result = elf64_get_dynamic_section(&image->elf, &dyn, &dyn_count);
    if (result == OE_OK)
    {
        needed_image_entry_t* prev_entry = NULL;

        /* Walk the dynamic entries to for needed images */
        for (size_t i = 0; i < dyn_count; i++)
        {
            if (dyn[i].d_tag == DT_NEEDED)
            {
                const char* name = elf64_get_string_from_dynstr(
                    &image->elf, dyn[i].d_un.d_val);
                if (!name)
                    OE_RAISE_MSG(
                        OE_INVALID_IMAGE,
                        "No name found for DT_NEEDED value %u",
                        dyn[i].d_un.d_val);

                /* Add the needed image name to the list */
                needed_image_entry_t* needed_image_entry =
                    (needed_image_entry_t*)malloc(sizeof(needed_image_entry_t));
                if (!needed_image_entry)
                    OE_RAISE(OE_OUT_OF_MEMORY);
                needed_image_entry->name = name;

                if (prev_entry == NULL)
                {
                    OE_SLIST_INSERT_HEAD(
                        &needed_image_list_head, needed_image_entry, next);
                    prev_entry = needed_image_entry;
                }
                else
                {
                    OE_SLIST_INSERT_AFTER(prev_entry, needed_image_entry, next);
                }

                image->num_needed_images++;
            }
        }

        /* Load each of the needed images found */
        if (image->num_needed_images > 0)
        {
            image->needed_images = (oe_enclave_elf_image_t*)calloc(
                1, sizeof(oe_enclave_elf_image_t) * image->num_needed_images);
            if (!image->needed_images)
                OE_RAISE(OE_OUT_OF_MEMORY);

            size_t image_index = 0;
            needed_image_entry_t* current = NULL;
            OE_SLIST_FOREACH(current, &needed_image_list_head, next)
            {
                if (image_index >= image->num_needed_images)
                    OE_RAISE(OE_OUT_OF_BOUNDS);

                /* All dependency images must be loaded from same folder as
                 * primay enclave */
                size_t name_length = strlen(current->name);
                needed_image_path =
                    (char*)malloc(path_length + name_length + 1);
                if (!needed_image_path)
                    OE_RAISE(OE_OUT_OF_MEMORY);
                sprintf(
                    needed_image_path,
                    "%.*s%s",
                    (int)path_length,
                    path,
                    current->name);

                OE_CHECK(_load_elf_image(
                    needed_image_path, &image->needed_images[image_index]));

                image_index++;
                free(needed_image_path);
                needed_image_path = NULL;
            }
        }
    }
    else if (result != OE_NOT_FOUND)
    {
        /* Raise failure result other than OE_NOT_FOUND */
        OE_RAISE(result);
    }

    result = OE_OK;

done:
    if (needed_image_path)
        free(needed_image_path);

    while (!OE_SLIST_EMPTY(&needed_image_list_head))
    {
        needed_image_entry_t* current = OE_SLIST_FIRST(&needed_image_list_head);
        OE_SLIST_REMOVE_HEAD(&needed_image_list_head, next);
        free(current);
    }

    if (result != OE_OK)
    {
        if (image->needed_images)
            free(image->needed_images);
        image->needed_images = NULL;
        image->num_needed_images = 0;
    }

    return result;
}

static size_t _get_folder_path_length(const char* path, int path_length)
{
    int i = 0;
    if (path_length > 0)
    {
        for (i = path_length - 1; i >= 0 && path[i] != '/' && path[i] != '\\';
             i--)
        {
        }

        /* Length includes final path separator */
        i++;
    }
    assert(i >= 0);
    return (size_t)i;
}

/* Loads an ELF binary into memory and parses it for addition into the enclave
 * The caller is expected to have zeroed the output image memory buffer and is
 * responsible for calling _unload_elf_image on the resulting buffer when done.
 */
static oe_result_t _load_elf_image(
    const char* path,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_ehdr_t* ehdr = NULL;

    assert(image && path);

    size_t path_length = strlen(path);
    if (path_length > OE_INT32_MAX)
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER,
            "Enclave path is not null-terminated or exceeds OE_INT32_MAX");

    OE_CHECK(_read_elf_header(path, image, &ehdr));

    OE_CHECK(_read_sections(ehdr, image));

    OE_CHECK(_initialize_image_segments(ehdr, image));

    OE_CHECK(_stage_image_segments(ehdr, image));

    /* Load the relocations into memory (zero-padded to next page size) */
    if (elf64_load_relocations(
            &image->elf, &image->reloc_data, &image->reloc_size) != 0)
        OE_RAISE(OE_INVALID_IMAGE);

    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_VERBOSE)
        _dump_relocations(image->reloc_data, image->reloc_size);

    /* Load any additional needed images */
    size_t folder_path_length =
        _get_folder_path_length(path, (int32_t)path_length);
    OE_CHECK(_load_needed_images(path, folder_path_length, image));

    image->elf.magic = ELF_MAGIC;
    result = OE_OK;

done:
    if (result != OE_OK)
    {
        _unload_elf_image(image);
    }
    return result;
}

static oe_result_t _sum_elf_image_size(
    const oe_enclave_elf_image_t* image,
    size_t* image_size)
{
    *image_size += image->image_size + image->reloc_size;
    for (size_t i = 0; i < image->num_needed_images; i++)
    {
        _sum_elf_image_size(&image->needed_images[i], image_size);
    }
    return OE_OK;
}

static oe_result_t _calculate_size(
    const oe_enclave_image_t* image,
    size_t* image_size)
{
    *image_size = 0;
    return (_sum_elf_image_size(&image->elf, image_size));
}

// ------------------------------------------------------------------

/*
**==============================================================================
**
** Image layout:
**
**     NHEAP = number of heap pages
**     NSTACK = number of stack pages
**     NTCS = number of TCS objects
**     GUARD = an unmapped guard page
**
**     [PAGES]:
**         [PROGRAM-PAGES]
**         [HEAP-PAGE]*NHEAP
**         ( [GUARD] [STACK-PAGE]*NSTACK [TCS-PAGES]*1 ) * NTCS
**
**     [PROGRAM-PAGES]:
**         [CODE-PAGES]: flags=reg|x|r content=(ELF segment)
**         [DATA-PAGES]: flags=reg|w|r content=(ELF segment)
**
**     [RELOCATION-PAGES]:
**
**     [HEAP-PAGES]: flags=reg|w|r content=0x00000000
**
**     [THREAD-PAGES]:
**         [GUARD-PAGE]
**         [STACK-PAGES]: flags=reg|w|r content=0xCCCCCCCC
**         [GUARD-PAGE]
**         [TCS-PAGE]
**         [SSA1-PAGE1]: flags=reg|w|r content=0x00000000 SSA-slot 0
**         [SSA2-PAGE2]: flags=reg|w|r content=0x00000000 SSA-slot 1
**         [GUARD-PAGE]
**         [SEG1-PAGE]: flags=reg|w|r content=0x00000000 FS or GS segment
**         [SEG2-PAGE]: flags=reg|w|r content=0x00000000 FS or GS segment
**
**==============================================================================
*/

static uint64_t _make_secinfo_flags(uint32_t flags)
{
    uint64_t r = 0;

    if (flags & PF_R)
        r |= SGX_SECINFO_R;

    if (flags & PF_W)
        r |= SGX_SECINFO_W;

    if (flags & PF_X)
        r |= SGX_SECINFO_X;

    return r;
}

static oe_result_t _add_relocation_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_base,
    uint64_t enclave_add_base,
    const void* reloc_data,
    const size_t reloc_size,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !vaddr)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reloc_data && reloc_size)
    {
        const oe_page_t* pages = (const oe_page_t*)reloc_data;
        size_t npages = reloc_size / sizeof(oe_page_t);

        for (size_t i = 0; i < npages; i++)
        {
            uint64_t addr = enclave_add_base + *vaddr;
            uint64_t src = (uint64_t)&pages[i];
            uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R;
            bool extend = true;

            OE_CHECK(oe_sgx_load_enclave_data(
                context, enclave_base, addr, src, flags, extend));
            (*vaddr) += sizeof(oe_page_t);
        }
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_segment_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_base,
    uint64_t enclave_add_base,
    const oe_elf_segment_t* segment,
    void* image)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t flags;
    uint64_t page_rva;
    uint64_t segment_end;

    assert(context);
    assert(segment);
    assert(image);

    /* Take into account that segment base address may not be page aligned */
    page_rva = oe_round_down_to_page_size(segment->vaddr);
    segment_end = segment->vaddr + segment->memsz;
    flags = _make_secinfo_flags(segment->flags);

    if (flags == 0)
    {
        OE_RAISE_MSG(
            OE_UNEXPECTED, "Segment with no page protections found.", NULL);
    }

    flags |= SGX_SECINFO_REG;

    for (; page_rva < segment_end; page_rva += OE_PAGE_SIZE)
    {
        OE_CHECK(oe_sgx_load_enclave_data(
            context,
            enclave_base,
            enclave_add_base + page_rva,
            (uint64_t)image + page_rva,
            flags,
            true));
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_elf_image_pages(
    oe_enclave_elf_image_t* image,
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    uint64_t* vaddr,
    uint64_t enclave_add_base)
{
    oe_result_t result = OE_UNEXPECTED;

    assert(context);
    assert(enclave);
    assert(image);
    assert(vaddr && (*vaddr == 0));
    assert((image->image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert(enclave->size > image->image_size);

    /* Add the program segments first */
    for (size_t i = 0; i < image->num_segments; i++)
    {
        OE_CHECK(_add_segment_pages(
            context,
            enclave->addr,
            enclave_add_base,
            &image->segments[i],
            image->image_base));
    }

    *vaddr = image->image_size;

    /* Add the relocation pages (contain relocation entries) */
    OE_CHECK(_add_relocation_pages(
        context,
        enclave->addr,
        enclave_add_base,
        image->reloc_data,
        image->reloc_size,
        vaddr));

    /* Repeat for all needed dependency images */
    enclave_add_base += image->image_size + image->reloc_size;
    for (size_t i = 0; i < image->num_needed_images; i++)
    {
        uint64_t needed_image_vaddr = 0;
        OE_CHECK(_add_elf_image_pages(
            &image->needed_images[i],
            context,
            enclave,
            &needed_image_vaddr,
            enclave_add_base));
        enclave_add_base += image->needed_images[i].image_size +
                            image->needed_images[i].reloc_size;
        *vaddr += needed_image_vaddr;
    }
    result = OE_OK;

done:
    return result;
}

/* Add image to enclave */
static oe_result_t _add_pages(
    oe_enclave_image_t* image,
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    uint64_t* vaddr)
{
    return _add_elf_image_pages(
        &image->elf, context, enclave, vaddr, enclave->addr);
}

static oe_result_t _get_dynamic_symbol_rva(
    oe_enclave_elf_image_t* image,
    const char* name,
    uint64_t* rva)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_sym_t sym = {0};

    if (!image || !name || !rva)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (elf64_find_dynamic_symbol_by_name(&image->elf, name, &sym) != 0)
        goto done;

    *rva = sym.st_value;
    result = OE_OK;
done:
    return result;
}

static oe_result_t _set_uint64_t_dynamic_symbol_value(
    oe_enclave_elf_image_t* image,
    const char* name,
    uint64_t value)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_sym_t sym = {0};
    uint64_t* symbol_address = NULL;

    if (elf64_find_dynamic_symbol_by_name(&image->elf, name, &sym) != 0)
        goto done;

    symbol_address = (uint64_t*)(image->image_base + sym.st_value);
    *symbol_address = value;

    result = OE_OK;
done:
    return result;
}

static oe_result_t _patch_elf_headers(oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Clear certain ELF header fields */
    for (size_t i = 0; i < image->num_segments; i++)
    {
        const oe_elf_segment_t* segment = &image->segments[i];
        elf64_ehdr_t* ehdr =
            (elf64_ehdr_t*)(image->image_base + segment->vaddr);

        if (elf64_test_header(ehdr) == 0)
        {
            ehdr->e_shoff = 0;
            ehdr->e_shnum = 0;
            ehdr->e_shstrndx = 0;
            break;
        }
    }

    for (size_t i = 0; i < image->num_needed_images; i++)
        OE_CHECK(_patch_elf_headers(&image->needed_images[i]));

    result = OE_OK;

done:
    return result;
}

static void _update_module_offset(
    oe_enclave_elf_image_t* image,
    uint64_t* module_offset)
{
    /* Note that this is an implicit contract with the _add_pages impl */
    *module_offset += image->image_size + image->reloc_size;
    for (size_t i = 0; i < image->num_needed_images; i++)
        _update_module_offset(&image->needed_images[i], module_offset);
}

static oe_result_t _link_elf_images(
    oe_enclave_elf_image_t* image,
    uint64_t* module_base)
{
    oe_result_t result = OE_UNEXPECTED;
    if (image->num_needed_images > 0)
    {
        OE_TRACE_INFO("Performing program linking\n");

        // Iterate through relocations in first image.
        elf64_rela_t* relocs = (elf64_rela_t*)image->reloc_data;
        uint64_t nrelocs = image->reloc_size / sizeof(relocs[0]);
        OE_TRACE_INFO("num relocs = %lu\n", nrelocs);

        const elf64_sym_t* symtab = NULL;
        size_t symtab_size = 0;
        if (elf64_get_dynamic_symbol_table(
                &image->elf, &symtab, &symtab_size) != 0)
            goto done;

        for (size_t i = 0; i < nrelocs; i++)
        {
            elf64_rela_t* p = &relocs[i];

            /* If zero-padded bytes reached */
            if (p->r_offset == 0)
                break;

            uint64_t sym_idx = ELF64_R_SYM(p->r_info);
            uint64_t reloc_type = ELF64_R_TYPE(p->r_info);

            /* Fix links to secondary module */
            if (reloc_type == R_X86_64_GLOB_DAT)
            {
                const elf64_sym_t* sym = &symtab[sym_idx];
                const char* name =
                    elf64_get_string_from_dynstr(&image->elf, sym->st_name);
                if (name == NULL)
                    OE_RAISE(OE_NOT_FOUND);

                OE_TRACE_INFO(
                    "Linking symbol '%s' with idx %lu", name, sym_idx);

                // Find the definition of the symbol from the needed images.
                uint64_t module_offset =
                    *module_base + image->image_size + image->reloc_size;
                size_t image_index = 0;
                for (; image_index < image->num_needed_images; image_index++)
                {
                    /* TODO: Search of direct dependencies is not comprehensive,
                     * the linker would actually need to generate a dependency
                     * graph to do the relocations for symbols provided by
                     * previously loaded modules.
                     */
                    elf64_sym_t sym_defn = {0};
                    if (elf64_find_dynamic_symbol_by_name(
                            &image->needed_images[image_index].elf,
                            name,
                            &sym_defn) == 0)
                    {
                        p->r_addend =
                            (int64_t)(module_offset + sym_defn.st_value);
                        OE_TRACE_INFO(
                            "'%s' vaddr=#%lx, r_addend = #%lx",
                            name,
                            sym_defn.st_value,
                            p->r_addend);
                        break;
                    }

                    _update_module_offset(
                        &image->needed_images[image_index], &module_offset);
                }

                if (image_index >= image->num_needed_images)
                    OE_TRACE_INFO(
                        "symbol %s not found in needed images\n", name);
            }
        }
    }

    /* Repeat for the rest of the images */
    *module_base += image->image_size + image->reloc_size;
    for (size_t i = 0; i < image->num_needed_images; i++)
    {
        OE_CHECK(_link_elf_images(&image->needed_images[i], module_base));
    }

    result = OE_OK;
done:
    return result;
}

static oe_result_t _patch_elf_image(
    oe_enclave_elf_image_t* image,
    oe_sgx_load_context_t* context,
    size_t enclave_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sgx_enclave_properties_t* oeprops;
    uint64_t enclave_rva = 0;
    uint64_t aligned_size = 0;
    uint64_t module_base = 0;

    oeprops =
        (oe_sgx_enclave_properties_t*)(image->image_base + image->oeinfo_rva);

    assert((image->image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert((image->reloc_size & (OE_PAGE_SIZE - 1)) == 0);
    assert((enclave_size & (OE_PAGE_SIZE - 1)) == 0);

    OE_CHECK(_patch_elf_headers(image));

    oeprops->image_info.enclave_size = enclave_size;
    oeprops->image_info.oeinfo_rva = image->oeinfo_rva;
    oeprops->image_info.oeinfo_size = sizeof(oe_sgx_enclave_properties_t);

    /* Set _enclave_rva to its own rva offset*/
    OE_CHECK(_get_dynamic_symbol_rva(image, "_enclave_rva", &enclave_rva));
    OE_CHECK(
        _set_uint64_t_dynamic_symbol_value(image, "_enclave_rva", enclave_rva));

    /* reloc right after image */
    oeprops->image_info.reloc_rva = image->image_size;
    oeprops->image_info.reloc_size = image->reloc_size;
    OE_CHECK(_set_uint64_t_dynamic_symbol_value(
        image, "_reloc_rva", image->image_size));
    OE_CHECK(_set_uint64_t_dynamic_symbol_value(
        image, "_reloc_size", image->reloc_size));

    /* heap right after image */
    oeprops->image_info.heap_rva = 0;
    OE_CHECK(_sum_elf_image_size(image, &oeprops->image_info.heap_rva));

    if (image->tdata_size)
    {
        _set_uint64_t_dynamic_symbol_value(
            image, "_tdata_rva", image->tdata_rva);
        _set_uint64_t_dynamic_symbol_value(
            image, "_tdata_size", image->tdata_size);
        _set_uint64_t_dynamic_symbol_value(
            image, "_tdata_align", image->tdata_align);

        aligned_size +=
            oe_round_up_to_multiple(image->tdata_size, image->tdata_align);
    }
    if (image->tbss_size)
    {
        _set_uint64_t_dynamic_symbol_value(
            image, "_tbss_size", image->tbss_size);
        _set_uint64_t_dynamic_symbol_value(
            image, "_tbss_align", image->tbss_align);

        aligned_size +=
            oe_round_up_to_multiple(image->tbss_size, image->tbss_align);
    }

    aligned_size = oe_round_up_to_multiple(aligned_size, OE_PAGE_SIZE);
    _set_uint64_t_dynamic_symbol_value(
        image,
        "_td_from_tcs_offset",
        aligned_size + OE_SGX_NUM_CONTROL_PAGES * OE_PAGE_SIZE);
    context->num_tls_pages = aligned_size / OE_PAGE_SIZE;

    /* Clear the hash when taking the measure */
    memset(oeprops->sigstruct, 0, sizeof(oeprops->sigstruct));

    /* Dynamically link the enclave and its needed modules */
    OE_CHECK(_link_elf_images(image, &module_base));

    result = OE_OK;
done:
    return result;
}

static oe_result_t _patch(
    oe_enclave_image_t* image,
    oe_sgx_load_context_t* context,
    size_t enclave_size)
{
    return _patch_elf_image(&image->elf, context, enclave_size);
}

static oe_result_t _sgx_load_enclave_properties(
    const oe_enclave_image_t* image,
    const char* section_name,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    OE_UNUSED(section_name);

    /* Copy from the image at oeinfo_rva. */
    OE_CHECK(oe_memcpy_s(
        properties,
        sizeof(*properties),
        image->elf.image_base + image->elf.oeinfo_rva,
        sizeof(*properties)));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _sgx_update_enclave_properties(
    const oe_enclave_image_t* image,
    const char* section_name,
    const oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    OE_UNUSED(section_name);

    /* Copy to both the image and ELF file*/
    OE_CHECK(oe_memcpy_s(
        (uint8_t*)image->elf.elf.data + image->elf.oeinfo_file_pos,
        sizeof(*properties),
        properties,
        sizeof(*properties)));

    OE_CHECK(oe_memcpy_s(
        image->elf.image_base + image->elf.oeinfo_rva,
        sizeof(*properties),
        properties,
        sizeof(*properties)));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_load_elf_enclave_image(
    const char* path,
    oe_enclave_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;

    memset(image, 0, sizeof(oe_enclave_image_t));

    /* Load the program segments into memory */
    OE_CHECK(_load_elf_image(path, &image->elf));

    /* Verify that primary enclave image properties are found */
    if (!image->elf.entry_rva)
        OE_RAISE_MSG(
            OE_UNSUPPORTED_ENCLAVE_IMAGE,
            "Enclave image is missing entry point.",
            NULL);

    if (!image->elf.oeinfo_rva || !image->elf.oeinfo_file_pos)
        OE_RAISE_MSG(
            OE_UNSUPPORTED_ENCLAVE_IMAGE,
            "Enclave image is missing .oeinfo section.",
            NULL);

    image->type = OE_IMAGE_TYPE_ELF;
    image->calculate_size = _calculate_size;
    image->add_pages = _add_pages;
    image->sgx_patch = _patch;
    image->sgx_load_enclave_properties = _sgx_load_enclave_properties;
    image->sgx_update_enclave_properties = _sgx_update_enclave_properties;
    image->unload = _unload_image;

    result = OE_OK;

done:

    if (OE_OK != result)
        _unload_image(image);

    return result;
}
