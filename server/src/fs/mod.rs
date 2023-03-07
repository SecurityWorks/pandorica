use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::ObjectStore;

#[allow(dead_code)]
pub struct FileSystem {
    #[allow(dead_code)]
    file_store: Box<dyn ObjectStore>,
}

impl FileSystem {
    // TODO: Add support for GCS, AWS S3, Azure Blob Storage
    // https://docs.rs/object_store/latest/object_store/
    #[allow(dead_code)]
    pub fn new(file_store: &str) -> Self {
        let file_store: Box<dyn ObjectStore> = match file_store {
            "local" => Self::construct_local_fs(),
            "memory" => Self::construct_memory_fs(),
            _ => panic!("Unknown file store"),
        };

        Self { file_store }
    }

    fn construct_local_fs() -> Box<LocalFileSystem> {
        let prefix = std::env::current_dir()
            .map_err(|e| panic!("Failed to get current directory: {}", e))
            .unwrap();
        let fs = LocalFileSystem::new_with_prefix(prefix.join("data").as_path())
            .map_err(|e| panic!("Failed to get current directory: {}", e))
            .unwrap();
        Box::new(fs)
    }

    fn construct_memory_fs() -> Box<InMemory> {
        Box::new(InMemory::new())
    }
}
