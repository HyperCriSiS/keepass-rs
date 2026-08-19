pub(crate) mod attachment;
pub(crate) mod autotype;
pub(crate) mod color;
pub(crate) mod custom_data;
pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod history;
pub(crate) mod icon;
pub(crate) mod meta;
pub(crate) mod times;
pub(crate) mod value;

use std::collections::HashMap;

pub use attachment::{Attachment, AttachmentId, AttachmentMut, AttachmentRef};
pub use autotype::{AutoType, AutoTypeAssociation, DataTransferObfuscation};
pub use color::{Color, ParseColorError};
pub use custom_data::{CustomDataItem, CustomDataValue};
pub use entry::{DestinationGroupNotFoundError, Entry, EntryId, EntryMut, EntryRef, EntryTrack};
pub use group::{
    DuplicateEntryIdError, DuplicateGroupIdError, Group, GroupId, GroupMut, GroupRef, GroupTrack,
    MoveGroupError,
};
pub use history::History;
pub use icon::{CustomIcon, CustomIconId, CustomIconMut, CustomIconNotFoundError, CustomIconRef, Icon};
pub use meta::{MemoryProtection, Meta};
pub use times::Times;
pub use value::Value;

use crate::config::DatabaseConfig;

use chrono::NaiveDateTime;
use uuid::Uuid;

/// A decrypted KeePass database
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Database {
    /// Configuration settings of the database such as encryption and compression algorithms
    pub config: DatabaseConfig,

    /// Metadata of the KeePass database
    pub meta: Meta,

    /// Root node of the KeePass database
    pub(crate) root: GroupId,

    /// All attachments in the database, stored in a flat HashMap
    pub(crate) attachments: HashMap<AttachmentId, Attachment>,

    /// All custom icons in the database, stored in a flat HashMap
    pub(crate) custom_icons: HashMap<CustomIconId, CustomIcon>,

    /// All entries in the database, stored in a flat HashMap
    pub(crate) entries: HashMap<EntryId, Entry>,

    /// All groups in the database, stored in a flat HashMap
    pub(crate) groups: HashMap<GroupId, Group>,

    /// References to previously-deleted objects and their deletion times.
    pub deleted_objects: HashMap<Uuid, Option<NaiveDateTime>>,

    /// XML paths that the tolerant KDBX deserializer did not model.
    ///
    /// These paths are retained as compatibility diagnostics so callers can keep read support
    /// tolerant while refusing a potentially lossy save. The ignored values themselves are not
    /// retained and therefore cannot be serialized safely by this engine.
    #[cfg_attr(feature = "serialization", serde(skip))]
    pub(crate) ignored_xml_paths: Vec<String>,
}

impl Database {
    /// Create a new database with a single root group and no entries, groups, or attachments.
    ///
    /// The root group will be assigned a new random UUID.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::new_with_root_id(GroupId::new())
    }

    /// Create a new database with the given configuration and a single root group.
    ///
    /// The root group will be assigned a new random UUID.
    pub fn with_config(config: DatabaseConfig) -> Self {
        Self::with_data(config, GroupId::new())
    }

    /// Create a new database with the given group UUID
    pub fn new_with_root_id(root_id: GroupId) -> Self {
        let root = Group::with_id(root_id, None);

        let mut groups = HashMap::new();
        groups.insert(root_id, root);

        Database {
            config: DatabaseConfig::default(),
            meta: Meta::default(),
            root: root_id,
            attachments: HashMap::new(),
            custom_icons: HashMap::new(),
            entries: HashMap::new(),
            groups,
            deleted_objects: HashMap::new(),
            ignored_xml_paths: Vec::new(),
        }
    }

    pub(crate) fn with_data(config: DatabaseConfig, root_id: GroupId) -> Self {
        let root = Group::with_id(root_id, None);

        let mut groups = HashMap::new();
        groups.insert(root_id, root);

        Database {
            config,
            meta: Meta::default(),
            root: root_id,
            attachments: HashMap::new(),
            custom_icons: HashMap::new(),
            entries: HashMap::new(),
            groups,
            deleted_objects: HashMap::new(),
            ignored_xml_paths: Vec::new(),
        }
    }

    /// Return XML paths that were ignored by the tolerant deserializer.
    ///
    /// A non-empty result means this engine did not model all source XML and callers must treat
    /// ordinary serialization as potentially lossy.
    pub fn ignored_xml_paths(&self) -> &[String] {
        &self.ignored_xml_paths
    }

    /// Whether the source contained XML fields not modeled by this engine.
    pub fn has_ignored_xml_fields(&self) -> bool {
        !self.ignored_xml_paths.is_empty()
    }

    /// Get an immutable reference to the root group of the database.
    pub fn root(&self) -> GroupRef<'_> {
        GroupRef::new(self, self.root)
    }

    /// Get a mutable reference to the root group of the database.
    pub fn root_mut(&mut self) -> GroupMut<'_> {
        GroupMut::new(self, self.root)
    }

    /// Get an immutable reference to the recycle bin group, if it exists
    pub fn recycle_bin(&self) -> Option<GroupRef<'_>> {
        let recyclebin_id = self.meta.recyclebin_uuid.map(GroupId::from_uuid)?;
        self.group(recyclebin_id)
    }

    /// Get a mutable reference to the recycle bin group, if it exists
    pub fn recycle_bin_mut(&mut self) -> Option<GroupMut<'_>> {
        let recyclebin_id = self.meta.recyclebin_uuid.map(GroupId::from_uuid)?;
        self.group_mut(recyclebin_id)
    }

    /// Get the number of attachments in the database
    pub fn num_attachments(&self) -> usize {
        self.attachments.len()
    }

    /// Get the number of custom icons in the database
    pub fn num_custom_icons(&self) -> usize {
        self.custom_icons.len()
    }

    /// Get the number of entries in the database
    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    /// Get the number of groups in the database
    pub fn num_groups(&self) -> usize {
        self.groups.len()
    }

    /// Get an immutable group by id
    pub fn group(&self, id: GroupId) -> Option<GroupRef<'_>> {
        self.groups.get(&id).map(|_| GroupRef::new(self, id))
    }

    /// Get a mutable group by id
    pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut<'_>> {
        self.groups.get(&id).map(|_| GroupMut::new(self, id))
    }

    /// Get an immutable entry by id
    pub fn entry(&self, id: EntryId) -> Option<EntryRef<'_>> {
        self.entries.get(&id).map(|_| EntryRef::new(self, id))
    }

    /// Get a mutable entry by id
    pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut<'_>> {
        self.entries.get(&id).map(|_| EntryMut::new(self, id))
    }

    /// Get an immutable attachment by id
    pub fn attachment(&self, id: AttachmentId) -> Option<AttachmentRef<'_>> {
        self.attachments.get(&id).map(|_| AttachmentRef::new(self, id))
    }

    /// Get a mutable attachment by id
    pub fn attachment_mut(&mut self, id: AttachmentId) -> Option<AttachmentMut<'_>> {
        self.attachments.get(&id).map(|_| AttachmentMut::new(self, id))
    }

    /// Get an immutable custom icon by id
    pub fn custom_icon(&self, id: CustomIconId) -> Option<CustomIconRef<'_>> {
        self.custom_icons.get(&id).map(|_| CustomIconRef::new(self, id))
    }

    /// Get a mutable custom icon by id
    pub fn custom_icon_mut(&mut self, id: CustomIconId) -> Option<CustomIconMut<'_>> {
        self.custom_icons.get(&id).map(|_| CustomIconMut::new(self, id))
    }

    /// Get an iterator over all entries in the database
    pub fn entries(&self) -> impl Iterator<Item = EntryRef<'_>> + '_ {
        self.entries.keys().map(|id| EntryRef::new(self, *id))
    }

    /// Get an iterator over all groups in the database
    pub fn groups(&self) -> impl Iterator<Item = GroupRef<'_>> + '_ {
        self.groups.keys().map(|id| GroupRef::new(self, *id))
    }

    /// Get an iterator over all attachments in the database
    pub fn attachments(&self) -> impl Iterator<Item = AttachmentRef<'_>> + '_ {
        self.attachments.keys().map(|id| AttachmentRef::new(self, *id))
    }

    /// Get an iterator over all custom icons in the database
    pub fn custom_icons(&self) -> impl Iterator<Item = CustomIconRef<'_>> + '_ {
        self.custom_icons.keys().map(|id| CustomIconRef::new(self, *id))
    }
}
