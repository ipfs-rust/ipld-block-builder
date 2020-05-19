use crate::cid::Cid;
pub use libipld::path::Path as IpldPath;

/// Path in a dag.
#[derive(Clone, Debug, PartialEq, Hash)]
pub struct DagPath<'a>(&'a Cid, IpldPath);

impl<'a> DagPath<'a> {
    /// Create a new dag path.
    pub fn new<T: Into<IpldPath>>(cid: &'a Cid, path: T) -> Self {
        Self(cid, path.into())
    }

    /// Returns the root of the path.
    pub fn root(&self) -> &Cid {
        self.0
    }

    /// Returns the ipld path.
    pub fn path(&self) -> &IpldPath {
        &self.1
    }
}

impl<'a> From<&'a Cid> for DagPath<'a> {
    fn from(cid: &'a Cid) -> Self {
        Self(cid, Default::default())
    }
}
