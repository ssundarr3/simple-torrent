use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct FakeData {
    pub bytes: Vec<u8>,
    pub files: Vec<(PathBuf, usize)>,
}

impl FakeData {
    pub fn file_data(&self, file_index: usize) -> &[u8] {
        let start: usize = self.files[..file_index]
            .iter()
            .map(|(_, file_size)| file_size)
            .sum();
        let end: usize = start + self.files[file_index].1;
        &self.bytes[start..end]
    }

    /// Generates fake data of `data_len` size across `file_percents.len()` files.
    /// `file_percents` determines the % data in each file. `file_percents` must sum to 100.
    pub fn generate(data_len: usize, file_percents: Vec<usize>) -> FakeData {
        assert_eq!(file_percents.iter().sum::<usize>(), 100);

        let mut bytes = Vec::with_capacity(data_len);
        let mut c: usize = 42;
        for i in 0..data_len {
            c = 2 * (c + i); // Make c look somewhat random.
            c = (c % 88) + 40; // Make c a printable character.
            bytes.push(c as u8);
        }
        dbg!(bytes::Bytes::copy_from_slice(&bytes[..50]));

        let files: Vec<(PathBuf, usize)> = if file_percents == [100] {
            vec![(["outfile.txt"].iter().collect(), data_len)]
        } else {
            let mut files = vec![];
            let mut start_percent = 0;
            for (i, percent) in file_percents.iter().enumerate() {
                let filepath: PathBuf = ["out_dir", &format!("file_{}", i)].iter().collect();

                let end_percent = start_percent + percent;
                let start_index = (data_len * start_percent) / 100;
                let end_index = (data_len * end_percent) / 100;
                let file_len = end_index - start_index;

                files.push((filepath, file_len));

                start_percent += percent;
            }
            files
        };

        assert_eq!(files.iter().map(|(_, len)| len).sum::<usize>(), data_len);

        FakeData { bytes, files }
    }
}
