use region::page;

/// Validates and rounds an address-size pair to their respective page boundary.
pub(crate) fn __round_to_page_boundaries<T>(
    address: *const T, size: usize,
) -> region::Result<(*const T, usize)> {
    if size == 0usize {
        return Err(region::Error::InvalidParameter("size"));
    }

    Ok((
        page::floor(address),
        page::ceil((address as usize % page::size()).saturating_add(size) as *const T) as usize,
    ))
}
