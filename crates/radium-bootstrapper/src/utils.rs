#[macro_export]
macro_rules! lazy_export {
    ($(fn $f:ident($($i:ident: $a:ty),*) -> $r:ty);+;) => {
        #[inline]
        #[must_use]
        pub fn __h_version() -> ::windows::Win32::Foundation::HINSTANCE {
            static VERSION: ::once_cell::sync::OnceCell<::windows::Win32::Foundation::HINSTANCE> = ::once_cell::sync::OnceCell::new();

            *VERSION.get_or_init(|| unsafe {
                ::windows::Win32::System::LibraryLoader::LoadLibraryA(s!(
                    r"C:\Windows\System32\version.dll"
                ))
                .unwrap()
            })
        }

        ::paste::paste! {
            $(
                #[export_name = "" $f ""]
                unsafe extern "system" fn [<__ $f:snake>]($($i: $a),*) -> $r {
                    unsafe {
                        ::std::mem::transmute::<
                            ::std::option::Option<unsafe extern "system" fn() -> isize>,
                            unsafe extern "system" fn($($a),*) -> $r,
                        >(::windows::Win32::System::LibraryLoader::GetProcAddress(
                            __h_version(),
                            ::windows::core::PCSTR(
                                ::std::stringify!($f)
                                    .as_bytes()
                                    .iter()
                                    .copied()
                                    .chain(once(0u8))
                                    .collect::<::std::vec::Vec<::std::primitive::u8>>()
                                    .as_ptr(),
                            ),
                        ))($($i),*)
                    }
                }
            )*
        }
    }
}
