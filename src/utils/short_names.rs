//! Taken from `bevy_utils`. See: <https://github.com/bevyengine/bevy/blob/e1a8123145ef3ea5d0d90135b5af6cb8979fb774/crates/bevy_utils/src/short_names.rs>

/// Shortens a type name to remove all module paths.
///
/// The short name of a type is its full name as returned by
/// [`any::type_name`], but with the prefix of all paths removed. For
/// example, the short name of [`alloc::vec::Vec<core::option::Option<u32>>`]
/// would be [`Vec<Option<u32>>`].
#[inline]
pub fn get_short_name(full_name: &str) -> String {
    // Generics result in nested paths within <..> blocks.
    // Consider "bevy_render::camera::camera::extract_cameras<bevy_render::camera::bundle::Camera3d>".
    // To tackle this, we parse the string from left to right, collapsing as we go.
    let mut index: usize = 0;
    let end_of_string = full_name.len();
    let mut parsed_name = String::new();

    while index < end_of_string {
        let rest_of_string = full_name.get(index..end_of_string).unwrap_or_default();

        // Collapse everything up to the next special character,
        // then skip over it
        if let Some(special_character_index) = rest_of_string.find(|c: char| {
            (c == ' ')
                || (c == '<')
                || (c == '>')
                || (c == '(')
                || (c == ')')
                || (c == '[')
                || (c == ']')
                || (c == ',')
                || (c == ';')
        }) {
            let segment_to_collapse = rest_of_string
                .get(0..special_character_index)
                .unwrap_or_default();

            parsed_name += collapse_type_name(segment_to_collapse);

            // Insert the special character
            let special_character =
                &rest_of_string[special_character_index..=special_character_index];

            parsed_name.push_str(special_character);

            match special_character {
                ">" | ")" | "]"
                    if rest_of_string[special_character_index + 1..].starts_with("::") =>
                {
                    parsed_name.push_str("::");
                    // Move the index past the "::"
                    index += special_character_index + 3;
                }
                // Move the index just past the special character
                _ => index += special_character_index + 1,
            }
        } else {
            // If there are no special characters left, we're done!
            parsed_name += collapse_type_name(rest_of_string);
            index = end_of_string;
        }
    }

    parsed_name
}

#[inline(always)]
fn collapse_type_name(string: &str) -> &str {
    #[allow(clippy::unwrap_used)]
    string.split("::").last().unwrap()
}
