use std::env;
use std::fs;
use std::thread;
use std::time::{Duration, SystemTime};
use time::{format_description, OffsetDateTime};

// Some information I found on the internet for the fields:
// See https://utcc.utoronto.ca/~cks/space/blog/linux/SmapsFields?showcomments#comments

// For each VMA mapping that gets listed in smaps, the kernel walks all
// of the PTEs associated with it and looks at all of the known pages. Each
// PTE is then counted up:
//
//  - the full PTE size is counted as Rss.
//  - if the page has been used recently, it's added to Referenced.
//  - if the page is mapped in only one process it is labeled as private;
//    its full size is added to Pss.
// - if the page is mapped in more than one process it is shared and the
//   amount it adds to Pss is divided by the number of processes that have it
//   mapped.
//
// (If the PTE is for something in swap it only adds to the Swap size.)
//
// Note that a 'private' page is not quite as private as you might
// think. Because processes map pages independently of each other, it's
// possible to have a shared page that is currently mapped only by a single
// process (eg only one process may have called an obscure libc function
// recently); such pages are counted in 'private'.
//
// The Size of a mapping is how much address space it covers.
//
// If the mapping has been locked into memory via mlock() or the like,
// Locked is the same as Pss (ie, it is this process's fair share of the
// amount of locked memory for this mapping); otherwise it is 0 kB.

#[derive(Debug)]
struct Map {
    pub start: u64,
    end: u64,
    pub flags: String,
    pub hex: String,       // what is this?
    pub device_major: u32, // correct guess?
    pub device_minor: u32, // correct guess?
    pub number: String,    // what is this?
    pub name: String,
    pub size: u64, // all in kB
    pub kernel_page_size: u64,
    pub mmu_page_size: u64,
    pub rss: u64,
    pub pss: u64,
    pub shared_clean: u64,
    pub shared_dirty: u64,
    pub private_clean: u64,
    pub private_dirty: u64,
    pub referenced: u64,
    pub anonymous: u64,
    pub lazy_free: u64,
    pub anon_huge_pages: u64,
    pub shmem_pmd_mapped: u64,
    pub file_pmd_mapped: u64,
    pub shared_huge_tlb: u64,
    pub private_huge_tlb: u64,
    pub swap: u64,
    pub swap_pss: u64,
    pub locked: u64,
    pub thp_eligible: bool,
    pub protection_key: u64,
    pub vmflags: String,
}

impl Map {
    pub fn parse_from_line_iterator(lines: &mut std::str::Lines) -> Result<Option<Map>, String> {
        let get_line = |lines: &mut std::str::Lines, first| -> Result<String, String> {
            let head = lines.next();
            match head {
                None => {
                    if first {
                        return Ok("".to_string());
                    } else {
                        return Err("Expecting more lines!".to_string());
                    }
                }
                Some(s) => Ok(s.to_string()),
            }
        };
        let first_line = get_line(lines, true)?;
        if first_line.is_empty() {
            return Ok(None);
        }
        let items: Vec<String> = first_line.split_whitespace().map(str::to_string).collect();
        if items.len() < 5 {
            return Err(format!("Found strange first line: {}", &first_line));
        }
        let bounds: Vec<String> = items[0].split("-").map(str::to_string).collect();
        if bounds.len() != 2 {
            return Err(format!("Found bad bounds: {}", items[0]));
        }
        let devices: Vec<String> = items[3].split(":").map(str::to_string).collect();
        if devices.len() != 2 {
            return Err(format!("Found bad devices: {}", items[3]));
        }
        let mut further_lines: Vec<String> = vec![];
        loop {
            further_lines.push(get_line(lines, false)?);
            if further_lines.last().unwrap().starts_with("VmFlags") {
                break;
            }
        }
        let get_number = |s: &String| -> u64 {
            let parts: Vec<String> = s.split_whitespace().map(str::to_string).collect();
            if parts.len() < 2 {
                return 0;
            }
            return parts[1]
                .parse::<u64>()
                .expect(&format!("Expecting a number in this string in second place: {}", s)[..]);
        };
        let get_hex = |s: &String| -> Result<u64, String> {
            u64::from_str_radix(s, 16).map_err(|e| -> String { e.to_string() })
        };
        if further_lines.len() < 22 {
            return Err("Expected at least 23 lines for entry.".to_string());
        }
        let mut name: String = "".to_string();
        for i in 5..items.len() {
            name.push_str(&items[i][..]);
            name.push_str(" ");
        }
        Ok(Some(Map {
            start: get_hex(&bounds[0])?,
            end: get_hex(&bounds[1])?,
            flags: items[1].clone(),
            hex: items[2].clone(),
            device_major: get_hex(&devices[0])? as u32,
            device_minor: get_hex(&devices[1])? as u32,
            number: items[4].clone(),
            name,
            size: get_number(&further_lines[0]),
            kernel_page_size: get_number(&further_lines[1]),
            mmu_page_size: get_number(&further_lines[2]),
            rss: get_number(&further_lines[3]),
            pss: get_number(&further_lines[4]),
            shared_clean: get_number(&further_lines[5]),
            shared_dirty: get_number(&further_lines[6]),
            private_clean: get_number(&further_lines[7]),
            private_dirty: get_number(&further_lines[8]),
            referenced: get_number(&further_lines[9]),
            anonymous: get_number(&further_lines[10]),
            lazy_free: get_number(&further_lines[11]),
            anon_huge_pages: get_number(&further_lines[12]),
            shmem_pmd_mapped: get_number(&further_lines[13]),
            file_pmd_mapped: get_number(&further_lines[14]),
            shared_huge_tlb: get_number(&further_lines[15]),
            private_huge_tlb: get_number(&further_lines[16]),
            swap: get_number(&further_lines[17]),
            swap_pss: get_number(&further_lines[18]),
            locked: get_number(&further_lines[19]),
            thp_eligible: get_number(&further_lines[20]) != 0,
            protection_key: if further_lines.len() == 23 {
                get_number(&further_lines[21])
            } else {
                0
            },
            vmflags: further_lines[further_lines.len() - 1].clone(),
        }))
    }

    pub fn pretty_print(&self) {
        println!("Range: {:x}-{:x}", self.start, self.end);
        println!(
            "Flags: {}, hex: {}, device: {:x}:{:x}, number: {}",
            self.flags, self.hex, self.device_major, self.device_minor, self.number
        );
        println!("Name: {}", self.name);
        println!(
            "Kernel page size: {}, mmu page size: {}",
            self.kernel_page_size, self.mmu_page_size
        );
        println!("Size: {}, Rss: {}, Pss: {}", self.size, self.rss, self.pss);
        println!(
            "Shared clean: {}, shared dirty: {}, private clean: {}, private dirty: {}",
            self.shared_clean, self.shared_dirty, self.private_clean, self.private_dirty
        );
        println!(
            "Referenced: {}, anonymous: {}, lazy free: {}",
            self.referenced, self.anonymous, self.lazy_free
        );
        println!(
            "Anon huge pages: {}, shmem pmd mapped: {}, file pmd mapped: {}",
            self.anon_huge_pages, self.shmem_pmd_mapped, self.file_pmd_mapped
        );
        println!(
            "Shared huge tlb: {}, private huge tlb: {}, swap: {}, swap_pss: {}, locked: {}",
            self.shared_huge_tlb, self.private_huge_tlb, self.swap, self.swap_pss, self.locked
        );
        println!(
            "Thp eligible: {}, protection key: {}, vmflags: {}\n",
            self.thp_eligible, self.protection_key, self.vmflags
        );
    }
}

struct Maps {
    pub pid: i32,
    pub time: SystemTime,
    pub maps: Vec<Map>,
}

impl Maps {
    fn get_maps(pid: i32) -> Result<Maps, String> {
        let filename = format!("/proc/{}/smaps", pid);
        let file =
            fs::read_to_string(&filename).expect(&format!("Cannot read file {}", filename)[..]);
        let mut lines = file.lines();
        let mut res = Maps {
            pid,
            time: SystemTime::now(),
            maps: vec![],
        };
        loop {
            let m = Map::parse_from_line_iterator(&mut lines);
            match m {
                Err(e) => {
                    return Err(format!("Could not parse map: {}", e));
                }
                Ok(mm) => {
                    if mm.is_none() {
                        return Ok(res);
                    }
                    res.maps.push(mm.unwrap());
                }
            }
        }
    }

    fn print_diff(&self, prev: &Maps) {
        assert_eq!(self.pid, prev.pid);
        let prev_time: OffsetDateTime = prev.time.into();
        let new_time: OffsetDateTime = self.time.into();
        println!(
            "\nDifferences in maps of pid {} between {} and {}:",
            self.pid,
            prev_time
                .format(&format_description::well_known::Rfc3339)
                .unwrap(),
            new_time
                .format(&format_description::well_known::Rfc3339)
                .unwrap(),
        );
        // We assume that both maps are sorted by start address!
        let mut i: usize = 0; // position in self.maps
        let mut j: usize = 0; // position in prev.maps
        while i < self.maps.len() && j < prev.maps.len() {
            let m = &self.maps[i];
            let p = &prev.maps[j];
            if m.start < p.start {
                if !m.name.is_empty() {
                    println!(
                        "MMAP: {:x}-{:x} size={} rss={} {}",
                        m.start, m.end, m.size, m.rss, m.name
                    );
                }
                i += 1;
            } else if m.start > p.start {
                if !p.name.is_empty() {
                    println!(
                        "DROP: {:x}-{:x} size={} rss={} {}",
                        p.start, p.end, p.size, p.rss, p.name
                    );
                }
                j += 1;
            } else {
                // Same map, see if there was a diff:
                let enddiff = if m.end != p.end {
                    format!(" (was {})", p.end)
                } else {
                    "".to_string()
                };
                let sizediff = if m.size != p.size {
                    format!(" (was {})", p.size)
                } else {
                    "".to_string()
                };
                let rssdiff = if m.rss != p.rss {
                    format!(" (was {})", p.rss)
                } else {
                    "".to_string()
                };
                if !enddiff.is_empty() || !sizediff.is_empty() || !rssdiff.is_empty() {
                    println!(
                        "CHANGED: {:x}-{:x}{} size={}{} rss={}{} {}",
                        m.start, m.end, enddiff, m.size, sizediff, m.rss, rssdiff, m.name
                    );
                }
                i += 1;
                j += 1;
            }
        }
        if i < self.maps.len() {
            while i < self.maps.len() {
                let m = &self.maps[i];
                if !m.name.is_empty() {
                    println!(
                        "MMAP: {:x}-{:x} size={} rss={} {}",
                        m.start, m.end, m.size, m.rss, m.name
                    );
                }
                i += 1;
            }
        }
        if j < self.maps.len() {
            while j < prev.maps.len() {
                let m = &prev.maps[j];
                if !m.name.is_empty() {
                    println!(
                        "DROP: {:x}-{:x} size={} rss={} {}",
                        m.start, m.end, m.size, m.rss, m.name
                    );
                }
                j += 1;
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: mapwatcher PID DELAY");
        std::process::exit(0);
    }
    let pid = args[1].parse::<i32>().expect("Need PID as first argument");
    let delay = args[2]
        .parse::<f64>()
        .expect("Need delay in seconds as second argument");
    let mut prev_maps = Maps::get_maps(pid).expect("Could not read initial maps.");
    println!("Got initial maps of process:");
    for m in prev_maps.maps.iter() {
        m.pretty_print();
    }
    println!("Starting to observe...\n");
    loop {
        thread::sleep(Duration::from_secs_f64(delay));
        let m = Maps::get_maps(pid);
        if let Err(e) = m {
            eprintln!("Could not get maps: {}", e);
            break;
        }
        let m = m.unwrap();
        m.print_diff(&prev_maps);
        prev_maps = m;
    }
    println!("Goodbye!");
}
