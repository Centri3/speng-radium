use once_cell::sync::OnceCell;
use windows::s;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::LibraryLoader::LoadLibraryA;

// #[inline]
// #[must_use]
// fn __h_version() -> &'static HINSTANCE {
//     static VERSION: OnceCell<HINSTANCE> = OnceCell::new();

//     VERSION.get_or_init(|| unsafe { LoadLibraryA(s!(r"C:\Windows\System32\version.dll")).unwrap() })
// }

#[macro_export]
macro_rules! lazy_export {
    ($(fn $f:ident($($i:ident: $a:ty),*) -> $r:ty);+;) => {
        ::paste::paste! {
            $(
                #[export_name = "" $f ""]
                unsafe extern "system" fn [<__ $f:snake>]($($i: $a),*) -> $r {
                    unsafe { $f($($i),*) }
                }
            )*
        }
    }
}
