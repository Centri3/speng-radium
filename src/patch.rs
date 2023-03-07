pub type FnFirst = fn();
pub type FnEarlier = Box<dyn Fn()>;
pub type FnBefore = Box<dyn Fn() -> bool>;
pub type FnReplace = Box<dyn Fn()>;
pub type FnAfter = Box<dyn Fn()>;
pub type FnLast = Box<dyn Fn()>;
pub type FnFinal = fn();
pub type Patches = (
    Vec<FnFirst>,
    Option<FnEarlier>,
    Vec<FnBefore>,
    Option<FnReplace>,
    Option<FnAfter>,
    Vec<FnLast>,
    Option<FnFinal>,
);

pub fn run_patches((first, earlier, before, replace, after, last, fin): Patches) {
    for func in first {
        func();
    }

    if let Some(earlier) = earlier {
        earlier();
    }

    let mut run_original = true;
    for func in before {
        if !func() {
            run_original = false;
        }
    }

    if run_original {
        if let Some(replace) = replace {
            replace();
        }
    }

    if let Some(after) = after {
        after();
    }

    for func in last {
        func();
    }

    if let Some(fin) = fin {
        fin();
    }
}
