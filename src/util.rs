/// Returns `ceil(a / b)`.
///
/// ## Examples
/// ```
/// assert_eq!(simple_torrent::util::div_ceil(10, 1), 10);
/// assert_eq!(simple_torrent::util::div_ceil(10, 3), 4);
/// assert_eq!(simple_torrent::util::div_ceil(10, 9), 2);
/// assert_eq!(simple_torrent::util::div_ceil(10, 10), 1);
/// assert_eq!(simple_torrent::util::div_ceil(10, 11), 1);
/// ```
///
/// ```should_panic
/// simple_torrent::util::div_ceil(10, 0); // Panics
/// ```
#[inline]
pub fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}
