use rand::prelude::*;
use region::alloc_at;
use region::page;
use region::query_range;
use region::Allocation;
use region::Protection;
use region::Region;

/// Allocates memory within 2GB of `address`.
///
/// RIIR from: <https://stackoverflow.com/a/54732489>
pub(crate) fn __alloc_at_2gb<T>(
    address: *const T,
    size: usize,
    protection: Protection,
) -> region::Result<Allocation> {
    let mut thread_rng = thread_rng();

    // FIXME: God damn this is stupid but at least it works, I guess?
    for _ in 0u32..1000u32 {
        let address = thread_rng.gen_range(
            (address as usize).saturating_sub(0x80000000usize)
                ..(address as usize).saturating_add(0x80000000usize) - size * page::size(),
        );

        if let Ok(a) = alloc_at(address as *const T, size, protection) {
            return Ok(a);
        }
    }

    Err(region::Error::UnmappedRegion)
}

/// Validates all of the pages in a queried range are mapped.
pub(crate) fn __query_range_checked<T>(
    address: *const T,
    size: usize,
) -> region::Result<Vec<Region>> {
    let query = query_range(address, size)?
        .flatten()
        .collect::<Vec<Region>>();

    match query.len() == __round_to_page_boundaries(address, size)?.1 / page::size() {
        true => Ok(query),
        false => Err(region::Error::UnmappedRegion),
    }
}

/// Validates and rounds an address-size pair to their respective page boundary.
///
/// Taken from: <https://github.com/darfink/region-rs/blob/master/src/util.rs#L3>
pub(crate) fn __round_to_page_boundaries<T>(
    address: *const T,
    size: usize,
) -> region::Result<(*const T, usize)> {
    if size == 0usize {
        return Err(region::Error::InvalidParameter("size"));
    }

    Ok((
        page::floor(address),
        page::ceil((address as usize % page::size()).saturating_add(size) as *const T) as usize,
    ))
}
