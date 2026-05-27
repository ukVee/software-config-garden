//! Walk the parent chain from a starting commit (default: tip) toward
//! genesis. Linear history → no merge resolution; we just follow `parent`.

use softfig_store::{CommitRow, Db, Hash};

use crate::error::Result;

/// Iterator that walks parent links toward genesis. Terminates when it
/// reaches a commit whose `parent` is `None` (the genesis commit).
#[derive(Debug)]
pub struct LogIter<'a> {
    db: &'a Db,
    next: Option<Hash>,
    err: Option<crate::error::CoreError>,
}

impl<'a> LogIter<'a> {
    pub(crate) fn new(db: &'a Db, start: Hash) -> Self {
        Self {
            db,
            next: Some(start),
            err: None,
        }
    }

    pub fn into_error(self) -> Option<crate::error::CoreError> {
        self.err
    }
}

impl<'a> Iterator for LogIter<'a> {
    type Item = CommitRow;

    fn next(&mut self) -> Option<Self::Item> {
        let h = self.next.take()?;
        match self.db.get_commit(&h) {
            Ok(row) => {
                self.next = row.parent;
                Some(row)
            }
            Err(e) => {
                self.err = Some(e.into());
                None
            }
        }
    }
}

/// Convenience: collect the full log starting from `start`. Stops on the
/// first error and returns it.
pub fn collect(db: &Db, start: Hash) -> Result<Vec<CommitRow>> {
    let mut iter = LogIter::new(db, start);
    let mut out = Vec::new();
    for row in iter.by_ref() {
        out.push(row);
    }
    if let Some(e) = iter.into_error() {
        return Err(e);
    }
    Ok(out)
}
