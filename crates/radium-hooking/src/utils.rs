use region::page;
use region::query_range;
use region::Region;

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
