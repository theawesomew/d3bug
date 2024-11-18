use std::{collections::HashMap, fs::{self, read_to_string}, io::{self, Read, Write}, os::{raw::c_void, unix::{fs::FileExt, process::{self, CommandExt}}}, process::{Command, Stdio}, str::SplitTerminator};
use gimli::UnitType;
use nix::{
    libc::{kill, personality, siginfo_t, ADDR_NO_RANDOMIZE, SIGSEGV, SIGTERM, SIGTRAP}, sys::{ptrace::{self}, wait::{self, WaitStatus}}, unistd::{fork, ForkResult, Pid}
};
use object::{Object, ObjectSection};
use std::{borrow, env, error};

//static REGISTERS: &'static [&str] = &["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags", "cs", "orig_rax", "fs_base", "gs_base", "fs", "gs", "ss", "ds", "es"];

#[derive(Clone, Debug)]
pub struct Breakpoint {
    pid: Pid,
    address: u64,
    enabled: bool,
    saved_data: i64,
}

impl Breakpoint {
    pub fn enable (&mut self) {
        let data = ptrace::read(self.pid, self.address as *mut c_void).expect("ptrace(PTRACE_PEEK_DATA, ...) failed");

        self.saved_data = data & 0x00000000000000ff;

        let data_with_int3 = (data as u64 & 0xffffffffffffff00 as u64) | 0x00000000000000cc as u64;

        let _ = ptrace::write(self.pid, self.address as *mut c_void, data_with_int3 as i64);

        self.enabled = true;
    }

    pub fn disable (&mut self) {
        let data = ptrace::read(self.pid, self.address as *mut c_void).expect("ptrace(PTRACE_PEEK_DATA, ...) failed");

        let restored_data = (data as u64 & 0xffffffffffffff00 as u64) | self.saved_data as u64;

        let _ = ptrace::write(self.pid, self.address as *mut c_void, restored_data as i64);

        self.enabled = false;
    } 
}

pub struct Debugger {
    pid: Pid,
    program_name: String,
    breakpoints: HashMap<u64, Breakpoint>,
    initial_load_address: u64,
    line_data: HashMap<u64, u64>,
    debug_info_available: bool,
    stack_base_address: u64,
}

impl Debugger {
    pub fn run (&mut self) {
        let _ = wait::waitpid(self.pid, None)
            .expect("waitpid failed");
        self.initial_load_address();
        self.get_stack_address();

        loop {
            let mut str: String = String::new();
            print!("d3bug > ");
            io::stdout().flush().unwrap();
            let _ = match io::stdin().read_line(&mut str) {
                Ok(_) => {
                    if self.handle_command(&str) == -1 {
                        break;
                    }
                },
                Err(_) => panic!("What the fuck?!"),
            };
        };
    }

    pub fn initial_load_address (&mut self) {
        let process_map_path = format!("/proc/{}/maps", self.pid);
        let lines: Vec<String> = read_to_string(process_map_path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();

        let first_line = &lines[0];
        let first_line_split: Vec<&str> = first_line.split('-').collect();
        let base_address_str = first_line_split[0];
        self.initial_load_address = u64::from_str_radix(base_address_str, 16).expect("Invalid hexadecimal address");
        
        println!("Base address: 0x{:x}", self.initial_load_address);
    }

    pub fn get_stack_address (&mut self) {
        let process_map_path = format!("/proc/{}/maps", self.pid);
        let lines: Vec<String> = read_to_string(process_map_path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();

        let first_line = &lines[10];
        let split_lines: Vec<&str> = first_line.split(' ').collect();
        let first_line_entry_split: Vec<&str> = split_lines[0].split('-').collect();
        let base_address_str = first_line_entry_split[1];
        dbg!(base_address_str);
        self.stack_base_address = u64::from_str_radix(base_address_str, 16).expect("Invalid hexadecimal address");
        
        println!("Base address: 0x{:x}", self.stack_base_address);
    }

    pub fn handle_command(&mut self, command: &String) -> i8 {
        let split_command: Vec<&str> = match command.strip_suffix('\n') {
            Some(s) => s.split(' ').collect(),
            None => command.split(' ').collect(),
        };

        if split_command[0] == "continue" || split_command[0] == "run" {
            self.continue_execution();
        } else if split_command[0] == "break" {
            match split_command[1].strip_prefix("0x") {
                Some(s) => {
                    let address: u64 = u64::from_str_radix(s, 16).expect("Invalid hexadecimal address");
                    self.set_breakpoint(address);
                },
                None => {
                    if !self.debug_info_available {
                        println!("Source-level debugging is not supported due to its absence");
                        return 0;
                    }

                    let line = match u64::from_str_radix(split_command[1], 10) {
                        Ok(line) => line,
                        Err(_) => { 
                            println!("Invalid input");
                            0
                        }
                    };

                    if line == 0 {
                        return 0;
                    }

                    let address = self.get_line_address(line);

                    if address == 0 {
                        println!("No line in source of number {}!", line);
                    } else {
                        self.set_breakpoint(address);
                    }
                }    
            }
        } else if split_command[0] == "register" {
            if split_command[1] == "dump" {
                self.dump_registers();
            } else if split_command[1] == "read" {
                let value = self.read_register(split_command[2]);
                println!("{}: {:x}", split_command[2], value);
            } else if split_command[1] == "write" {
                match split_command[3].strip_prefix("0x") {
                    Some(s) => {
                        let value: u64 = u64::from_str_radix(s, 16).expect("Invalid hexadecimal address");
                        self.write_register(split_command[2], value);
                    },
                    None => {
                        println!("Please enter a hexdecimal value in the format 0x...");
                    }    
                }
            }
        } else if split_command[0] == "step" {
            self.step();
        } else if split_command[0] == "stack" {
            if split_command[1] == "dump" {
                let length = u64::from_str_radix(split_command[2], 10).expect("Invalid base10 int");
                self.dump_stack(length);
            } else {
                println!("Not all stack operations are currently supported!");
            }
        } else if split_command[0] == "exit" {
            unsafe { kill(self.pid.as_raw() as i32, SIGTERM) };
            return -1;
        } else {
            println!("Unknown command");
        }

        return 0;
    }

    pub fn get_line_address (&mut self, line: u64) -> u64 {
        match self.line_data.get(&line) {
            Some(address) => self.initial_load_address + address,
            None => 0
        }
    }

    pub fn dump_stack (&mut self, length: u64) {
        let process_memory_path = format!("/proc/{}/mem", self.pid);
        let process_memory = fs::File::open(process_memory_path).unwrap();
        let mut buf = vec![0; length as usize];

        match process_memory.read_at(&mut buf, self.stack_base_address - length) {
            Ok(_) => {
                println!("Stack: ");
                let mut s = self.stack_base_address - length;
                let mut i = 0;
                while i < length {
                    println!("0x{:x}", s);
                    i += 32;
                    s += 32;
                }
            },
            Err(_) => {}
        };
    }

    pub fn continue_execution (&mut self) {
        self.step_over_breakpoint();
        ptrace::cont(self.pid, None)
            .expect("ptrace(PTRACE_CONT, ...) failed");
        self.wait_for_signal();
    }

    pub fn step_over_breakpoint (&mut self) {
        let addr = self.get_pc();
        let mut breakpoints = self.breakpoints.clone();

        match breakpoints.get_mut(&addr) {
            Some(bp) => {
                if bp.enabled {
                    bp.disable();
                    let _ = ptrace::step(self.pid, None);
                    self.wait_for_signal();
                    bp.enable();
                }
            },
            None => {},
        }
    }

    pub fn step_over_instruction (&mut self) {
        let _ = ptrace::step(self.pid, None);
        self.wait_for_signal();
    }

    pub fn step (&mut self) {
        let breakpoints = self.breakpoints.clone();

        if breakpoints.contains_key(&self.get_pc()) {
            self.step_over_breakpoint();
        } else {
            self.step_over_instruction();
        }
    }

    pub fn get_signal_info (&mut self) -> siginfo_t {
        let siginfo = ptrace::getsiginfo(self.pid).expect("Failed to get signal information");
        return siginfo;
    }

    pub fn wait_for_signal (&mut self) {
        let status = wait::waitpid(self.pid, None)
            .expect("waitpid failed");

        if status == WaitStatus::Exited(self.pid, 0) {
            return;
        }

        let siginfo = self.get_signal_info();

        match siginfo.si_signo {
            SIGTRAP => self.handle_signal(siginfo),
            SIGSEGV => println!("Segmentation fault. Reason: {}", siginfo.si_code),
            _ => println!("Got signal, {}", siginfo.si_signo.to_string()),
        }
    }

    pub fn handle_signal (&mut self, siginfo: siginfo_t) {
        match siginfo.si_code {
            128 => {
               let addr= self.get_pc() - 1;
               self.set_pc(addr);
               println!("Hit break point at 0x{:x}", self.get_pc());
            }
            2 => {}
            _ => {
                println!("Unknown signal code {}", siginfo.si_code);
            }
        }
    }

    pub fn set_breakpoint (&mut self, address: u64) {
        println!("Set breakpoint at {:x}", address);

        let mut bp = Breakpoint {
            pid: self.pid,
            address: address,
            enabled: false,
            saved_data: 0,
        };

        bp.enable();
        self.breakpoints.insert(address, bp);
    } 

    pub fn read_register(&mut self, reg: &str) -> u64 {
        let registers = ptrace::getregs(self.pid).unwrap();

        match reg {
            "rax" => registers.rax, 
            "rbx" => registers.rbx, 
            "rcx" => registers.rcx, 
            "rdx" => registers.rdx, 
            "rdi" => registers.rdi, 
            "rsi" => registers.rsi, 
            "rbp" => registers.rbp, 
            "rsp" => registers.rsp, 
            "r8" => registers.r8, 
            "r9" => registers.r9, 
            "r10" => registers.r10, 
            "r11" => registers.r11, 
            "r12" => registers.r12, 
            "r13" => registers.r13, 
            "r14" => registers.r14, 
            "r15" => registers.r15, 
            "rip" => registers.rip,
            "cs" => registers.cs, 
            "orig_rax" => registers.orig_rax, 
            "fs_base" => registers.fs_base, 
            "gs_base" => registers.gs_base, 
            "fs" => registers.fs, 
            "gs" => registers.gs, 
            "ss" => registers.ss, 
            "ds" => registers.ds, 
            "es" => registers.es,
            _ => {
                println!("Register does not exist");
                0
            },
        }
    }

    pub fn write_register(&mut self, reg: &str, value: u64) {
        let mut registers = ptrace::getregs(self.pid).unwrap();

        match reg {
            "rax" => {
                registers.rax = value;
            },
            "rbx" => {
                registers.rbx = value;
            }, 
            "rcx" => {
                registers.rcx = value;
            }, 
            "rdx" => { 
                registers.rdx = value;
            }, 
            "rdi" => { 
                registers.rdi = value;
            }, 
            "rsi" => { 
                registers.rsi = value; 
            }, 
            "rbp" => { 
                registers.rbp = value;
            },
            "rsp" => { 
                registers.rsp = value;
            }, 
            "r8" => { 
                registers.r8 = value;
            }, 
            "r9" => { 
                registers.r9 = value;
            }, 
            "r10" => { registers.r10 = value; }, 
            "r11" => { registers.r11 = value; }, 
            "r12" => { registers.r12 = value; }, 
            "r13" => { registers.r13 = value; }, 
            "r14" => { registers.r14 = value; }, 
            "r15" => { registers.r15 = value; }, 
            "rip" => { registers.rip = value; },
            "cs" => { registers.cs = value; }, 
            "orig_rax" => { registers.orig_rax = value; }, 
            "fs_base" => { registers.fs_base = value; }, 
            "gs_base" => { registers.gs_base = value; }, 
            "fs" => { registers.fs = value; }, 
            "gs" => { registers.gs = value; }, 
            "ss" => { registers.ss = value; }, 
            "ds" => { registers.ds = value; }, 
            "es" => { registers.es = value; },
            _ => {
                println!("Register does not exist");
            },
        }

        ptrace::setregs(self.pid, registers).expect("Failed to write to registers");
    }

    pub fn get_pc (&mut self) -> u64 {
        return self.read_register("rip");
    }

    pub fn set_pc (&mut self, value: u64) {
        self.write_register("rip", value);
    }

    pub fn dump_registers (&mut self) {
        let registers = ptrace::getregs(self.pid).unwrap();

        println!("rax: {:x}", registers.rax);
        println!("rbx: {:x}", registers.rbx);
        println!("rcx: {:x}", registers.rcx);
        println!("rdx: {:x}", registers.rdx);
        println!("rdi: {:x}", registers.rdi);
        println!("rsi: {:x}", registers.rsi);
        println!("rbp: {:x}", registers.rbp);
        println!("rsp: {:x}", registers.rsp);
        println!("r8: {:x}", registers.r8);
        println!("r9: {:x}", registers.r9);
        println!("r10: {:x}", registers.r10);
        println!("r11: {:x}", registers.r12);
        println!("r13: {:x}", registers.r13);
        println!("r14: {:x}", registers.r14);
        println!("r15: {:x}", registers.r15);
        println!("rip: {:x}", registers.rip);
        println!("cs: {:x}", registers.cs);
        println!("orig_rax: {:x}", registers.orig_rax);
        println!("fs_base: {:x}", registers.fs_base);
        println!("gs_base: {:x}", registers.gs_base);
        println!("fs: {:x}", registers.fs);
        println!("gs: {:x}", registers.gs);
        println!("ss: {:x}", registers.ss);
        println!("ds: {:x}", registers.ds);
        println!("es: {:x}", registers.es);
    }
}

// TODO: Read DWARF data and add to the debugger
// TODO: Restrict access to commands subject to whether or not DWARF data is available
// TODO: Implement record
// TODO: Implement restore

fn dump_file(object: &object::File, endian: gimli::RunTimeEndian) -> Result<HashMap<u64, u64>, Box<dyn error::Error>>{
    let mut result = HashMap::<u64,u64>::new();
    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, Box<dyn error::Error>> {
        Ok(match object.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?,
            None => borrow::Cow::Borrowed(&[]),
        })
    };

    let borrow_section = |section| gimli::EndianSlice::new(borrow::Cow::as_ref(section), endian);

    let dwarf_sections = gimli::DwarfSections::load(&load_section)?;

    let dwarf = dwarf_sections.borrow(borrow_section);

    let mut iter = dwarf.units();

    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        let unit = unit.unit_ref(&dwarf);

        if let Some(program) = unit.line_program.clone() {
            let mut rows = program.rows();
            while let Some((_, row)) = rows.next_row()? {
                if row.end_sequence() {
                    // this indicates some gap in addresses which is concerning
                } else {
                    let line = match row.line() {
                        Some(line) => line.get(),
                        None => 0,
                    };

                    if line != 0 { 
                        result.insert(line, row.address());
                    }
                }
            }
        }
    }
    
    return Ok(result);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            println!("Pid: {}", child);

            let file = fs::File::open(args[1].clone()).unwrap();
            let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
            let object = object::File::parse(&*mmap).unwrap();

            let line_data  = match dump_file(&object, gimli::RunTimeEndian::Little) {
                Ok(debug_info) => debug_info,
                Err(_) => {
                    println!("Error loading debugging information!");
                    HashMap::<u64,u64>::new()
                }
            };

            let debug_info_available = !line_data.is_empty();

            let mut dbg = Debugger {
                pid: child,
                program_name: args[1].clone(),
                breakpoints: HashMap::new(),
                initial_load_address: 0,
                line_data: line_data,
                debug_info_available: debug_info_available,
                stack_base_address: 0,
            };

            dbg.run();
        },
        Ok(ForkResult::Child) => {
            let _ = ptrace::traceme();
            unsafe { personality(ADDR_NO_RANDOMIZE as u64) };

            Command::new(args[1].clone())
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .exec();
        },
        Err(_) => {
            panic!("fork failed!");
        }
    }
}
