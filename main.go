package main

/*
typedef void(*run)(void);
void myexec(void* b) {
    ((run)b)();
}
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func main() {
	// exec([]byte{0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xc3})
	// exec([]byte{0xc3})

	if len(os.Args) < 2 {
		log.Fatalln("no input provided")
	}
	input := os.Args[1]

	f, err := os.Open(input)
	if err != nil {
		log.Fatalf("failed to open file %s: %s\n", input, err)
	}

	bf, err := io.ReadAll(f)
	if err != nil {
		log.Fatalf("failed to read from file %s: %s\n", input, err)
	}

	fmt.Printf("%s", bf)

	ops, err := transform(bf)
	if err != nil {
		log.Fatalf("failed to parse source: %s\n", err)
	}

	for _, op := range ops {
		fmt.Printf("%c %d\n", op.kind, op.operand)
	}

	// interpret(ops)

	fmt.Println("jitting...")
	code := jit(ops)
	exec(code)
}

type opKind rune

const (
	opKindNone         opKind = 0
	opKindInc          opKind = '+'
	opKindDec          opKind = '-'
	opKindLeft         opKind = '<'
	opKindRight        opKind = '>'
	opKindInput        opKind = ','
	opKindOutput       opKind = '.'
	opKindJumpForward  opKind = '['
	opKindJumpBackward opKind = ']'
)

type operation struct {
	kind    opKind
	operand int
}

// transform takes a brainfuck string and converts it to an
// intermediate representation of operations.
func transform(bf []byte) ([]operation, error) {
	ops := make([]operation, 0)

	jumpstack := make([]int, 0)

	op := &operation{}
	for _, c := range bf {
		switch c {
		case '+', '-', '<', '>', '.', ',':
			if op.kind != opKind(c) {
				ops = append(ops, operation{kind: opKind(c)})
				op = &ops[len(ops)-1]
			}
			op.operand++
		case '[':
			jumpstack = append(jumpstack, len(ops))

			ops = append(ops, operation{kind: opKind(c)})
			op = &ops[len(ops)-1]
		case ']':
			if len(jumpstack) == 0 {
				return nil, errors.New("unmatched bracket")
			}
			dst := jumpstack[len(jumpstack)-1]
			jumpstack = jumpstack[:len(jumpstack)-1]

			ops = append(ops, operation{kind: opKind(c)})
			op = &ops[len(ops)-1]

			// backpatch
			op.operand = dst + 1
			ops[dst].operand = len(ops)
		default:
			continue
		}
	}

	return ops, nil
}

func interpret(ops []operation) {
	mem := make([]byte, 1024) // memory
	mem_ptr := 0              // memory pointer
	ops_ptr := 0              // operation pointer
	for {
		if ops_ptr >= len(ops) {
			break
		}

		op := ops[ops_ptr]
		switch op.kind {
		case opKindInc:
			mem[mem_ptr] += byte(op.operand)
			ops_ptr++
		case opKindDec:
			mem[mem_ptr] -= byte(op.operand)
			ops_ptr++
		case opKindLeft:
			if mem_ptr < op.operand {
				panic("memory underflow")
			}
			mem_ptr -= op.operand
			ops_ptr++
		case opKindRight:
			mem_ptr += op.operand
			for range mem_ptr - len(mem) + 1 {
				mem = append(mem, 0)
			}
			ops_ptr++
		case opKindInput:
			panic("input not implemented")
		case opKindOutput:
			for range op.operand {
				os.Stdout.Write(mem[mem_ptr : mem_ptr+1])
			}
			ops_ptr++
		case opKindJumpForward:
			if mem[mem_ptr] == 0 {
				ops_ptr = op.operand
			} else {
				ops_ptr++
			}
		case opKindJumpBackward:
			if mem[mem_ptr] != 0 {
				ops_ptr = op.operand
			} else {
				ops_ptr++
			}
		}
	}
}

func exec(code []byte) {
	ccode, err := syscall.Mmap(
		-1,
		0,
		len(code),
		syscall.PROT_EXEC|syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS,
	)
	if err != nil {
		panic(err)
	}

	copy(ccode, code)

	var pin runtime.Pinner
	defer pin.Unpin()

	ccode_ptr := &ccode[0]
	pin.Pin(ccode_ptr)

	C.myexec(unsafe.Pointer(ccode_ptr))
}

type backpatch struct {
	srcAddr int // source address
	dstOp   int // destination operation index
}

func jit(ops []operation) []byte {
	code := make([]byte, 0)
	backpatches := make([]backpatch, 0)
	opaddrs := make([]int, 0)

	// Generate assembly for operations.
	// Memory will be allocated on the stack, using r8 as the mem_ptr
	// and expanding the stack as necessary.

	code = append(code, []byte{0x55}...)                   // push rbp
	code = append(code, []byte{0x48, 0x89, 0xe5}...)       // mov rbp, rsp
	code = append(code, []byte{0x6a, 0x00}...)             // push 0
	code = append(code, []byte{0x49, 0x89, 0xe0}...)       // mov r8, rsp
	code = append(code, []byte{0x49, 0x83, 0xc0, 0x07}...) // add r8, 7
	for _, op := range ops {
		opaddrs = append(opaddrs, len(code))
		switch op.kind {
		case opKindInc:
			code = append(code, []byte{0x41, 0x80, 0x00, uint8(op.operand)}...) // add byte [r8], <value>
		case opKindDec:
			code = append(code, []byte{0x41, 0x80, 0x28, uint8(op.operand)}...) // sub byte [r8], <value>
		case opKindLeft:
			code = append(code, []byte{0x49, 0x83, 0xc0, uint8(op.operand)}...) // add r8, <value>
		case opKindRight:
			code = append(code, []byte{0x49, 0x83, 0xe8, uint8(op.operand)}...) // sub r8, <value>
			// allocate more memory on the stack by pushing repeatedly until
			// the r8 address is greater or equal the rsp
			// start
			code = append(code, []byte{0x49, 0x39, 0xe0}...) // cmp r8, rsp
			code = append(code, []byte{0x73, 0x04}...)       // jnb stop
			code = append(code, []byte{0x6a, 0x00}...)       // push 0
			code = append(code, []byte{0xeb, 0xf7}...)       // jmp start
			// stop
		case opKindInput:
			panic("input not implemented")
		case opKindOutput:
			for range op.operand {
				code = append(code, []byte{0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00}...) // mov rax, 1
				code = append(code, []byte{0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00}...) // mov rdi, 1
				code = append(code, []byte{0x4c, 0x89, 0xc6}...)                         // mov rsi, r8
				code = append(code, []byte{0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00}...) // mov rdx, 1
				code = append(code, []byte{0x0f, 0x05}...)                               // syscall
			}
		case opKindJumpForward:
			code = append(code, []byte{0x41, 0x80, 0x38, 0x00}...)             // cmp byte [r8], 0
			code = append(code, []byte{0x0f, 0x84, 0x00, 0x00, 0x00, 0x00}...) // je <value>

			backpatches = append(backpatches, backpatch{srcAddr: len(code), dstOp: op.operand})
		case opKindJumpBackward:
			code = append(code, []byte{0x41, 0x80, 0x38, 0x00}...)             // cmp byte [r8], 0
			code = append(code, []byte{0x0f, 0x85, 0x00, 0x00, 0x00, 0x00}...) // jne <value>

			backpatches = append(backpatches, backpatch{srcAddr: len(code), dstOp: op.operand})
		}
	}
	code = append(code, []byte{0x48, 0x89, 0xec}...) // mov rsp, rbp
	code = append(code, []byte{0x5d}...)             // pop rbp
	code = append(code, 0xc3)                        // ret

	for _, bp := range backpatches {
		binary.LittleEndian.PutUint32(
			code[bp.srcAddr-4:bp.srcAddr],
			uint32(opaddrs[bp.dstOp]-bp.srcAddr),
		)
	}

	return code
}
