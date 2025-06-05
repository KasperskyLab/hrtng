/*
    Copyright © 2017-2025 AO Kaspersky Lab

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Author: Sergey.Belov at kaspersky.com
*/

// rewritten to c++ from python "AVX support for the Hex-Rays x64 Decompiler" plugin (https://github.com/gaasedelen/microavx.git)
// few more AVX instructions have been added

#include "warn_off.h"
#include <hexrays.hpp>
#include <intel.hpp>
#include "warn_on.h"

#include "helpers.h"

#if IDA_SDK_VERSION >= 750

// register widths (bytes)
#define XMM_SIZE 16
#define YMM_SIZE 32
#define ZMM_SIZE 64

// type sizes (bytes)
#define FLOAT_SIZE  4
#define DOUBLE_SIZE 8
#define DWORD_SIZE  4
#define QWORD_SIZE  8

// Return true if the given operand *looks* like a mem op.
bool is_mem_op(const op_t& op)  { return op.type == o_mem || op.type == o_displ || op.type == o_phrase; }
bool is_reg_op(const op_t& op)  { return op.type == o_reg; }
bool is_xmm_reg(const op_t& op) { return op.type == o_reg && op.dtype == dt_byte16; }
bool is_ymm_reg(const op_t& op) { return op.type == o_reg && op.dtype == dt_byte32; }
bool is_zmm_reg(const op_t& op) { return op.type == o_reg && op.dtype == dt_byte64; }
bool is_avx_reg(const op_t& op) { return op.type == o_reg && (op.dtype == dt_byte16 || op.dtype == dt_byte32); } // || op.dtype == dt_byte64);  }
bool is_avx_512(const insn_t &insn) { return evexpr(insn); }

//Return the YMM microcode register for a given XMM register.
mreg_t get_ymm_mreg(mreg_t xmm_mreg)
{
  int xmm_reg = mreg2reg(xmm_mreg, XMM_SIZE);
  QASSERT(100601, xmm_reg != -1);

  qstring xmm_name;
  ssize_t s = get_reg_name(&xmm_name, xmm_reg, XMM_SIZE);
  QASSERT(100602, s != -1);

  qstring ymm_name = "ymm";
  ymm_name += xmm_name.substr(3);
  int ymm_reg = str2reg(ymm_name.c_str());
  QASSERT(100603, ymm_reg != -1);

  mreg_t ymm_mreg = reg2mreg(ymm_reg);
  QASSERT(100604, ymm_mreg != mr_none);

  return ymm_mreg;
}

// Extend the given xmm reg, clearing the upper bits (through ymm).
minsn_t* clear_upper(codegen_t& cdg, mreg_t xmm_mreg, int op_size = XMM_SIZE)
{
  return cdg.emit(m_xdu, new mop_t(xmm_mreg, op_size), new mop_t(), new mop_t(get_ymm_mreg(xmm_mreg), YMM_SIZE));
}

#if IDA_SDK_VERSION < 760
// XXX: why is there a load_operand(), but no inverse.. ?
bool store_operand_hack(codegen_t &cdg, int n, const mop_t &mop, int flags=0, minsn_t **outins=nullptr)
{
    // emit a 'load' operation...
    mreg_t memX = cdg.load_operand(n);
    QASSERT(100605, memX != mr_none);

    // since this is gonna be kind of hacky, let's make sure a load was actually emitted
    minsn_t *ins = cdg.mb->tail;
    if (ins->opcode != m_ldx) {
      QASSERT(100606, ins->prev->opcode != m_ldx);
      minsn_t *prev = ins->prev;
      cdg.mb->make_nop(ins);
      ins = prev;
    }
    QASSERT(100607, ins->d.size == mop.size);

    // convert the load to a store :^)
    ins->opcode = m_stx;
    ins->d = ins->r;   // d = op mem offset
    ins->r = ins->l;   // r = op mem segm
    ins->l = mop;  // l = value to store (mop_t)

		if(outins)
			*outins = ins;
    return true;
}
#else //IDA_SDK_VERSION >= 760
bool store_operand_hack(codegen_t &cdg, int n, const mop_t &mop, int flags=0, minsn_t **outins=nullptr)
{
	return cdg.store_operand(n, mop, flags, outins);
}
#endif //IDA_SDK_VERSION < 760

// This class helps with generating simple intrinsic calls in microcode.
struct ida_local AVXIntrinsic
{
  codegen_t* cdg;
  mcallinfo_t *call_info;
  minsn_t* call_insn;
  minsn_t* mov_insn;

  AVXIntrinsic(codegen_t* cdg_, const char *name) : cdg(cdg_), mov_insn(nullptr)
  {
    call_info = new mcallinfo_t();
    call_info->cc = CM_CC_FASTCALL;
    call_info->flags = FCI_SPLOK | FCI_FINAL | FCI_PROP;
    call_insn = new minsn_t(cdg->insn.ea);
    call_insn->opcode = m_call;
    call_insn->l.make_helper(name);
    call_insn->d.t = mop_f;
    call_insn->d.f = call_info;
    call_info->return_type = tinfo_t();
    call_insn->d.size = 0;
  }

  //Set the return register of the function call, with a complex type.
  void set_return_reg(mreg_t mreg, tinfo_t ret_tinfo)
  {
    call_info->return_type = ret_tinfo;
    call_insn->d.size = (decltype(call_insn->d.size))ret_tinfo.get_size();
    mov_insn = new minsn_t(cdg->insn.ea);
    mov_insn->opcode = m_mov;
    mov_insn->l.make_insn(call_insn);
    mov_insn->l.size = call_insn->d.size;
    mov_insn->d.make_reg(mreg, call_insn->d.size);
    if (ret_tinfo.is_decl_floating())
      mov_insn->set_fpinsn();
  }

  //Set the return register of the function call, with a type string.
  void set_return_reg(mreg_t mreg, const char *type_string)
  {
    tinfo_t ret_tinfo;
    ret_tinfo.get_named_type(nullptr, type_string);
    set_return_reg(mreg, ret_tinfo);
  }

  //Set the return register of the function call, with a basic type assigned.
  void set_return_reg_basic(mreg_t mreg, type_t basic_type)
  {
    set_return_reg(mreg, tinfo_t(basic_type));
  }

  //Add a register argument of the given type to the function argument list.
  void add_argument_reg(mreg_t mreg, tinfo_t op_tinfo)
  {
    mcallarg_t call_arg(mop_t(mreg, (int)op_tinfo.get_size()));
    call_arg.type = op_tinfo;
    call_arg.size = (decltype(call_arg.size))op_tinfo.get_size();
    call_info->args.add(call_arg);
    call_info->solid_args++;
  }

  //Add a regeister argument with a given type string to the function argument list.
  void add_argument_reg(mreg_t mreg, const char* type_string)
  {
    tinfo_t op_tinfo;
    op_tinfo.get_named_type(nullptr, type_string);
    add_argument_reg(mreg, op_tinfo);
  }

  // Add a register argument with a basic type to the function argument list.
  void add_argument_reg(mreg_t mreg, type_t basic_type)
  {
    add_argument_reg(mreg, tinfo_t(basic_type));
  }

  // Add an immediate value to the function argument list.
  void add_argument_imm(uint64 value, type_t basic_type)
  {
    tinfo_t op_tinfo(basic_type);
    mcallarg_t call_arg;
    call_arg.make_number(value, (int)op_tinfo.get_size());
    call_arg.type = op_tinfo;
    call_arg.size = (decltype(call_arg.size))op_tinfo.get_size();
    call_info->args.add(call_arg);
    call_info->solid_args++;
  }

  minsn_t* emit()
  {
    QASSERT(100600, mov_insn != nullptr);
    return cdg->mb->insert_into_block(mov_insn, cdg->mb->tail);
  }
};


// A Hex-Rays microcode filter to lift AVX instructions during decompilation.
struct ida_local AVXLifter : microcode_filter_t {
  virtual bool match(codegen_t &cdg)
  {
    if (is_avx_512(cdg.insn))
      return false;

    switch(cdg.insn.itype) {
    // Compares (Scalar, Single / Double-Precision)
    case NN_vcomiss:
    case NN_vcomisd:
    case NN_vucomiss:
    case NN_vucomisd:
      // Extract
    case NN_vpextrb:
    case NN_vpextrw:
    case NN_vpextrd:
    case NN_vpextrq:
      // Conversions
    case NN_vcvttss2si:
    case NN_vcvtdq2ps:
    case NN_vcvtsi2ss:
    case NN_vcvtps2pd:
    case NN_vcvtss2sd:
      // Mov (DWORD / QWORD)
    case NN_vmovd:
    case NN_vmovq:
      // Mov (Scalar, Single / Double-Precision)
    case NN_vmovss:
    case NN_vmovsd:
      // Mov (Packed Single-Precision, Packed Integers)
    case NN_vmovaps:
    case NN_vmovups:
    case NN_vmovdqa:
    case NN_vmovdqu:
      // Bitwise (Scalar, Single / Double-Precision)
    case NN_vpor:
    case NN_vorps:
    case NN_vorpd:
    case NN_vpand:
    case NN_vandps:
    case NN_vandpd:
    case NN_vpxor:
    case NN_vxorps:
    case NN_vxorpd:
      // Math (Scalar Single-Precision)
    case NN_vaddss:
    case NN_vsubss:
    case NN_vmulss:
    case NN_vdivss:
      // Math (Scalar Double-Precision)
    case NN_vaddsd:
    case NN_vsubsd:
    case NN_vmulsd:
    case NN_vdivsd:
      // Math (Packed)
    case NN_vaddps:
    case NN_vsubps:
    case NN_vmulps:
    case NN_vdivps:
    case NN_vaddpd:
    case NN_vsubpd:
    case NN_vmulpd:
    case NN_vdivpd:
    case NN_vpaddb:
    case NN_vpsubb:
    case NN_vpaddw:
    case NN_vpsubw:
    case NN_vpaddd:
    case NN_vpsubd:
    case NN_vpaddq:
    case NN_vpsubq:
      // Square Root
    case NN_vsqrtss:
    case NN_vsqrtps:
      // Shuffle (Packed Single-Precision)
    case NN_vshufps:
      return true;
    }
    return false;
  }

  /// generate microcode for an instruction
  /// \return MERR_... code:
  ///   MERR_OK      - user-defined call generated, go to the next instruction
  ///   MERR_INSN    - not generated - the caller should try the standard way
  ///   else         - error
  virtual merror_t apply(codegen_t &cdg)
  {
    switch(cdg.insn.itype) {
    // Compares (Scalar, Single / Double-Precision)
		// the intel manual states that all of these comparison instructions are
		// effectively identical to their SSE counterparts. because of this, we
		// simply twiddle the decoded insn to make it appear as SSE and bail.
		//
		// since the decompiler appears to operate on the same decoded instruction
		// data that we meddled with, it will lift the instruction in the same way
		// it would lift the SSE version we alias each AVX one to.
    case NN_vcomiss:  cdg.insn.itype = NN_comiss;  return MERR_INSN;
    case NN_vcomisd:  cdg.insn.itype = NN_comisd;  return MERR_INSN;
    case NN_vucomiss: cdg.insn.itype = NN_ucomiss; return MERR_INSN;
    case NN_vucomisd: cdg.insn.itype = NN_ucomisd; return MERR_INSN;
    // Extract
    case NN_vpextrb: cdg.insn.itype = NN_pextrb;  return MERR_INSN;
    case NN_vpextrw: cdg.insn.itype = NN_pextrw;  return MERR_INSN;
    case NN_vpextrd: cdg.insn.itype = NN_pextrd;  return MERR_INSN;
    case NN_vpextrq: cdg.insn.itype = NN_pextrq;  return MERR_INSN;

      // Conversions
    case NN_vcvttss2si: cdg.insn.itype = NN_cvttss2si; return MERR_INSN;
    case NN_vcvtdq2ps: return vcvtdq2ps(cdg);
    case NN_vcvtsi2ss: return vcvtsi2ss(cdg);
    case NN_vcvtps2pd: return vcvtps2pd(cdg);
    case NN_vcvtss2sd: return vcvtss2sd(cdg);

      // Mov (DWORD / QWORD)
    case NN_vmovd: return _vmov(cdg, DWORD_SIZE);
    case NN_vmovq: return _vmov(cdg, QWORD_SIZE);

      // Mov (Scalar, Single / Double-Precision)
    case NN_vmovss: return _vmov_ss_sd(cdg, FLOAT_SIZE);
    case NN_vmovsd: return _vmov_ss_sd(cdg, DOUBLE_SIZE);

      // Mov (Packed Single-Precision, Packed Integers)
    case NN_vmovaps:
    case NN_vmovups:
    case NN_vmovdqa:
    case NN_vmovdqu:
      return v_mov_ps_dq(cdg);

      // Bitwise (Integer, Single / Double-Precision)
    case NN_vpor:
    case NN_vorps:
    case NN_vorpd:
    case NN_vpand:
    case NN_vandps:
    case NN_vandpd:
    case NN_vpxor:
    case NN_vxorps:
    case NN_vxorpd:
      return v_bitwise(cdg);

      // Math (Scalar Single-Precision)
    case NN_vaddss:
    case NN_vsubss:
    case NN_vmulss:
    case NN_vdivss:
      return _v_math_ss_sd(cdg, FLOAT_SIZE);

      // Math (Scalar Double-Precision)
    case NN_vaddsd:
    case NN_vsubsd:
    case NN_vmulsd:
    case NN_vdivsd:
      return _v_math_ss_sd(cdg, DOUBLE_SIZE);

      // Math (Packed)
    case NN_vaddps:
    case NN_vsubps:
    case NN_vmulps:
    case NN_vdivps:
    case NN_vaddpd:
    case NN_vsubpd:
    case NN_vmulpd:
    case NN_vdivpd:
    case NN_vpaddb:
    case NN_vpsubb:
    case NN_vpaddw:
    case NN_vpsubw:
    case NN_vpaddd:
    case NN_vpsubd:
    case NN_vpaddq:
    case NN_vpsubq:
      return v_math_p(cdg);

      // Square Root
    case NN_vsqrtss: return vsqrtss(cdg);
    case NN_vsqrtps: return vsqrtps(cdg);

      // Shuffle (Packed Single-Precision)
    case NN_vshufps: return vshufps(cdg);
    }
    return MERR_INSN;
  }



  //-------------------------------------------------------------------------
  // Conversion Instructions
  //-------------------------------------------------------------------------


  // VCVTDQ2PS xmm1, xmm2/m128
  // VCVTDQ2PS ymm1, ymm2/m256
  merror_t vcvtdq2ps(codegen_t &cdg)
  {
    int op_size = YMM_SIZE;
    if (is_xmm_reg(cdg.insn.Op1))
      op_size = XMM_SIZE;

    mreg_t r_reg;
    if (is_mem_op(cdg.insn.Op2)) {
      // op2 -- m128/m256
      r_reg = cdg.load_operand(1);
    } else {
      // op2 -- xmm2/ymm2
      QASSERT(100608, is_avx_reg(cdg.insn.Op2));
      r_reg = reg2mreg(cdg.insn.Op2.reg);
    }

    // op1 -- xmm1/ymm1
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg);

    // intrinsics:
    //     __m128 _mm_cvtepi32_ps (__m128i a)
    //     __m256 _mm256_cvtepi32_ps (__m256i a)

    qstring intrinsic_name;
    intrinsic_name.cat_sprnt("_mm%s_cvtepi32_ps", op_size == YMM_SIZE ? "256" : "");
    AVXIntrinsic avx_intrinsic(&cdg, intrinsic_name.c_str());

    uint32 bit_size = op_size * 8;
    qstring type_name;
    type_name.cat_sprnt("__m%u", bit_size);
    avx_intrinsic.set_return_reg(d_reg, type_name.c_str());

    type_name.append('i');
    avx_intrinsic.add_argument_reg(r_reg, type_name.c_str());
    avx_intrinsic.emit();

    // clear upper 128 bits of ymm1
    if (op_size == XMM_SIZE)
      clear_upper(cdg, d_reg);

    return MERR_OK;
  }

  // VCVTSI2SS xmm1, xmm2, r/m32
  // VCVTSI2SS xmm1, xmm2, r/m64
  merror_t vcvtsi2ss(codegen_t &cdg)
  {
    int src_size = (int)get_dtype_size(cdg.insn.Op3.dtype);
    mreg_t r_reg;
    if (is_mem_op(cdg.insn.Op3)) {
      // op3 -- m32/m64
      r_reg = cdg.load_operand(2);
    } else {
      // op3 -- r32/r64
      QASSERT(100609,is_reg_op(cdg.insn.Op3));
      r_reg = reg2mreg(cdg.insn.Op3.reg);
    }
    mreg_t l_reg = reg2mreg(cdg.insn.Op2.reg); // op2 -- xmm2
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmm1
    mreg_t t0_result = cdg.mba->alloc_kreg(XMM_SIZE);// create a temp register to compute the final result into
    mop_t* t0_mop = new mop_t(t0_result, FLOAT_SIZE);
    mreg_t t1_i2f = cdg.mba->alloc_kreg(src_size);   // create a temp register to downcast a double to a float (if needed)
    mop_t* t1_mop = new mop_t(t1_i2f, src_size);
    cdg.emit(m_mov, XMM_SIZE, l_reg, 0, t0_result, 0); // copy xmm2 into the temp result reg, as we need its upper 3 dwords
    cdg.emit(m_i2f, src_size, r_reg, 0, t1_i2f, 0);    // convert the integer (op3) to a float/double depending on its size
    cdg.emit(m_f2f, t1_mop, nullptr, t0_mop);          // reduce precision on the converted floating point value if needed (only r64/m64)
    cdg.emit(m_mov, XMM_SIZE, t0_result, 0, d_reg, 0); // transfer the fully computed temp register to the real dest reg
    cdg.mba->free_kreg(t0_result, XMM_SIZE);
    cdg.mba->free_kreg(t1_i2f, src_size);
    clear_upper(cdg, d_reg);// clear upper 128 bits of ymm1
    return MERR_OK;
  }

  // VCVTPS2PD xmm1, xmm2/m64
  // VCVTPS2PD ymm1, ymm2/m128
  merror_t vcvtps2pd(codegen_t &cdg)
  {
		int src_size = XMM_SIZE;
		if (is_xmm_reg(cdg.insn.Op1))
			src_size = QWORD_SIZE;

		mreg_t r_reg;
		if (is_mem_op(cdg.insn.Op2)) {
			// op2 -- m64/m128
			r_reg = cdg.load_operand(1);
		} else {
			// op2 -- xmm2/ymm2
			QASSERT(100610, is_avx_reg(cdg.insn.Op2));
			r_reg = reg2mreg(cdg.insn.Op2.reg);
		}

		mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmm1/ymm1

		// intrinsics:
		//   - __m128d _mm_cvtps_pd (__m128 a)
		//   - __m256d _mm256_cvtps_pd (__m128 a)
		qstring intrinsic_name;
		intrinsic_name.cat_sprnt("_mm%s_cvtps_pd", src_size * 2 == YMM_SIZE ? "256" : "");
		AVXIntrinsic avx_intrinsic(&cdg, intrinsic_name.c_str());
		avx_intrinsic.add_argument_reg(r_reg, "__m128");

		uint32 bit_size = src_size * 2 * 8;
		qstring type_name;
		type_name.cat_sprnt("__m%ud", bit_size);
		avx_intrinsic.set_return_reg(d_reg, type_name.c_str());
		avx_intrinsic.emit();

		// clear upper 128 bits of ymm1
		if (src_size == QWORD_SIZE)
			clear_upper(cdg, d_reg);
		return MERR_OK;
	}

  //VCVTSS2SD xmm1, xmm2, r/m32
  merror_t vcvtss2sd(codegen_t &cdg)
  {
    mreg_t r_reg;
    if (is_mem_op(cdg.insn.Op3)) {
      // op3 -- m32
      r_reg = cdg.load_operand(2);
    } else {
      // op3 -- r32
      QASSERT(100611, is_reg_op(cdg.insn.Op3));
      r_reg = reg2mreg(cdg.insn.Op3.reg);
    }
    mop_t* r_mop = new mop_t(r_reg, FLOAT_SIZE);
    mreg_t l_reg = reg2mreg(cdg.insn.Op2.reg); // op2 -- xmm2
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmm1
    mreg_t t0_result = cdg.mba->alloc_kreg(XMM_SIZE);  // create a temp register to compute the final result into
    mop_t* t0_mop = new mop_t(t0_result, DOUBLE_SIZE);
    cdg.emit(m_mov, XMM_SIZE, l_reg, 0, t0_result, 0); // copy xmm2 into the temp result reg, as we need its upper quadword
    cdg.emit(m_f2f, r_mop, nullptr, t0_mop);           // convert float (op3) to a double, storing it in the lower 64 of the temp result reg
    cdg.emit(m_mov, XMM_SIZE, t0_result, 0, d_reg, 0); // transfer the fully computed temp register to the real dest reg
    cdg.mba->free_kreg(t0_result, XMM_SIZE);
    clear_upper(cdg, d_reg);// clear upper 128 bits of ymm1
    return MERR_OK;
  }

  //-------------------------------------------------------------------------
  // Mov Instructions
  //-------------------------------------------------------------------------

  // VMOVSS xmm1, xmm2, xmm3
  // VMOVSS xmm1, m32
  // VMOVSS m32, xmm1
  // VMOVSD xmm1, m64
  // VMOVSD m64, xmm1
  //Templated handler for scalar float/double mov instructions.
  merror_t _vmov_ss_sd(codegen_t &cdg, int data_size)
  {
    if (cdg.insn.Op3.type == o_void) {
      // op form: X, Y -- (2 operands)
      if (is_xmm_reg(cdg.insn.Op1)) {
        // op form: xmm1, m32/m64
        QASSERT(100612, is_mem_op(cdg.insn.Op2));
        mop_t* l_mop = new mop_t(cdg.load_operand(1), data_size);  // op2 -- m32/m64
        mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmm1
        cdg.emit(m_xdu, l_mop, nullptr, new mop_t(d_reg, XMM_SIZE)); // xmm1[:data_size] = [mem]
        clear_upper(cdg, d_reg, data_size); // clear xmm1[data_size:] bits (through ymm1)
        return MERR_OK;
      } else {
        // op form: m32/m64, xmm1
        QASSERT(100613, is_mem_op(cdg.insn.Op1) && is_xmm_reg(cdg.insn.Op2));
        // store xmm1[:data_size] into memory at [m32/m64] (op1)
        minsn_t *outins=nullptr;
        if(store_operand_hack(cdg, 0, mop_t(reg2mreg(cdg.insn.Op2.reg), data_size), 0, &outins)) {
          outins->set_fpinsn();
          return MERR_OK;
        }
      }
      QASSERT(100614, "oops");
      return MERR_INSN;
    }
    // op form: xmm1, xmm2, xmm3 -- (3 operands)
    QASSERT(100615, is_xmm_reg(cdg.insn.Op1) && is_xmm_reg(cdg.insn.Op2) && is_xmm_reg(cdg.insn.Op3));
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg);
    mreg_t t0_result = cdg.mba->alloc_kreg(XMM_SIZE);
    cdg.emit(m_mov, XMM_SIZE, reg2mreg(cdg.insn.Op2.reg), 0, t0_result, 0);
    cdg.emit(m_f2f, data_size, reg2mreg(cdg.insn.Op3.reg), 0, t0_result, 0);
    cdg.emit(m_mov, XMM_SIZE, t0_result, 0, d_reg, 0);
    cdg.mba->free_kreg(t0_result, XMM_SIZE);
    clear_upper(cdg, d_reg, data_size);// clear xmm1[data_size:] bits (through ymm1)
    return MERR_OK;
  }

  /*
  VMOVD xmm1, r32/m32
  VMOVD r32/m32, xmm1
  VMOVQ xmm1, r64/m64
  VMOVQ r64/m64, xmm1
  VMOVAPS xmm1, xmm2/m128
  VMOVAPS ymm1, ymm2/m256
  VMOVAPS xmm2/m128, xmm1
  VMOVAPS ymm2/m256, ymm1
  */
  // Templated handler for dword/qword mov instructions.
  merror_t _vmov(codegen_t &cdg, int data_size)
  {
    if (is_xmm_reg(cdg.insn.Op1)) {
      // op form: xmm1, rXX/mXX
      mreg_t l_reg;
      if (is_mem_op(cdg.insn.Op2))
        l_reg = cdg.load_operand(1); // op2 -- m32/m64
      else
        l_reg = reg2mreg(cdg.insn.Op2.reg); // op2 -- r32/r64
      mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmm1
      cdg.emit(m_xdu, new mop_t(l_reg, data_size), nullptr, new mop_t(d_reg, XMM_SIZE));
      clear_upper(cdg, d_reg);// clear upper 128 bits of ymm1
      return MERR_OK;
    }
    // op form: rXX/mXX, xmm1
    QASSERT(100616, is_xmm_reg(cdg.insn.Op2));
    // op2 -- xmm1
    mreg_t l_reg = reg2mreg(cdg.insn.Op2.reg);
    if (is_mem_op(cdg.insn.Op1)) {
      // op1 -- m32/m64
      store_operand_hack(cdg, 0, mop_t(l_reg, data_size));
    } else {
      // op1 -- r32/r64
      cdg.emit(m_mov, new mop_t(l_reg, data_size), nullptr, new mop_t(reg2mreg(cdg.insn.Op1.reg), data_size));
      // TODO: the intel manual doesn't make it entierly clear here
      // if the upper bits of a r32 operation need to be cleared ?
    }
    return MERR_OK;
  }

  merror_t v_mov_ps_dq(codegen_t &cdg)
  {
    if (is_avx_reg(cdg.insn.Op1)) {
      // op form: reg, [mem]
      int op_size = YMM_SIZE;
      if (is_xmm_reg(cdg.insn.Op1))
        op_size = XMM_SIZE;
      mreg_t l_reg;
      if (is_mem_op(cdg.insn.Op2)) {
        // op2 -- m128/m256
        l_reg = cdg.load_operand(1);
      } else {
        // op2 -- xmm1/ymm1
        QASSERT(100617, is_avx_reg(cdg.insn.Op2));
        l_reg = reg2mreg(cdg.insn.Op2.reg);
      }
      mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmmX/ymmX
      cdg.emit(m_mov, new mop_t(l_reg, op_size), nullptr, new mop_t(d_reg, op_size));
      if (op_size == XMM_SIZE)
        clear_upper(cdg, d_reg);
      return MERR_OK;
    }
    // op form: [mem], reg
    QASSERT(100618, is_mem_op(cdg.insn.Op1) && is_avx_reg(cdg.insn.Op2));
    int op_size = YMM_SIZE;
    if (is_xmm_reg(cdg.insn.Op2))
      op_size = XMM_SIZE;
    // [m128/m256] = xmm1/ymm1
    store_operand_hack(cdg, 0, mop_t(reg2mreg(cdg.insn.Op2.reg), op_size));
    return MERR_OK;
  }

  //-------------------------------------------------------------------------
  // Bitwise Instructions
  //-------------------------------------------------------------------------

  // VORPS xmm1, xmm2, xmm3/m128
  // VORPS ymm1, ymm2, ymm3/m256
  merror_t v_bitwise(codegen_t &cdg)
  {
    QASSERT(100619, is_avx_reg(cdg.insn.Op1) && is_avx_reg(cdg.insn.Op2));
    int op_size = (int)get_dtype_size(cdg.insn.Op1.dtype);

    mreg_t r_reg;
    if (is_mem_op(cdg.insn.Op3)) {
      // op3 -- m128/m256
      r_reg = cdg.load_operand(2);
    } else {
      // op3 -- xmm3/ymm3
      QASSERT(100620, is_avx_reg(cdg.insn.Op3));
      r_reg = reg2mreg(cdg.insn.Op3.reg);
    }

    mcode_t mcode_op = m_nop;
    switch (cdg.insn.itype) {
    case NN_vpor:
    case NN_vorps:
    case NN_vorpd:
      mcode_op = m_or;
      break;
    case NN_vpand:
    case NN_vandps:
    case NN_vandpd:
      mcode_op = m_and;
      break;
    case NN_vpxor:
    case NN_vxorps:
    case NN_vxorpd:
      mcode_op = m_xor;
      break;
    default:
      QASSERT(100621, "wtf");
    }
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg);
    //cdg.emit(mcode_op, op_size, reg2mreg(cdg.insn.Op2.reg), r_reg, d_reg, -1); // INTERR(50801); // wrong FPINSN mark
    if (op_size > XMM_SIZE) {
      // dirty hack to avoid INTERR(50757) - bad operand size
      // WRONG SIZED pseudocode will be produced as result of this hack
      // I've no idea why XMM_SIZE is ok, but YMM_SIZE isn't ok. Is it probly bug in hex-rays mop_t::verify()?
      // set_udt() for l,r & d - helps to pass over this call cdg.emit() but later happens INTERR(50757) 
			Log(llWarning, "%a warning: 128bit operation is displayed instead of %dbit\n" , cdg.insn.ea, op_size * 8);
      op_size = XMM_SIZE;
    }
    mop_t* l = new mop_t(reg2mreg(cdg.insn.Op2.reg), op_size);
    mop_t* r = new mop_t(r_reg, op_size); 
    mop_t* d = new mop_t(d_reg, op_size); 
    cdg.emit(mcode_op, l, r, d);
    if (op_size == XMM_SIZE)
      clear_upper(cdg, d_reg);
    return MERR_OK;
  }

  //-------------------------------------------------------------------------
  // Arithmetic Instructions
  //-------------------------------------------------------------------------

  // VADDSS    xmm1, xmm2, xmm3/m32
  // VADDSD    xmm1, xmm2, xmm3/m64
  //Templated handler for scalar float/double math instructions.
  merror_t _v_math_ss_sd(codegen_t &cdg, int op_size)
  {
    QASSERT(100632, is_avx_reg(cdg.insn.Op1) && is_avx_reg(cdg.insn.Op2));
    mreg_t r_reg;
    if (is_mem_op(cdg.insn.Op3)) {
      // op3 -- m32/m64
      r_reg = cdg.load_operand(2);
    } else {
      // op3 -- xmm3
      QASSERT(100622, is_xmm_reg(cdg.insn.Op3));
      r_reg = reg2mreg(cdg.insn.Op3.reg);
    }
    mreg_t l_reg = reg2mreg(cdg.insn.Op2.reg); // op2 -- xmm2
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmm1
    mcode_t mcode_op = m_nop;
    switch(cdg.insn.itype) {
    case NN_vaddss:
    case NN_vaddsd:
      mcode_op = m_fadd;
      break;
    case NN_vsubss:
    case NN_vsubsd:
      mcode_op = m_fsub;
      break;
    case NN_vmulss:
    case NN_vmulsd:
      mcode_op = m_fmul;
      break;
    case NN_vdivss:
    case NN_vdivsd:
      mcode_op = m_fdiv;
      break;
    }
    op_dtype_t op_dtype = dt_double;
    if (op_size == FLOAT_SIZE)
      op_dtype = dt_float;
    mreg_t t0_result = cdg.mba->alloc_kreg(XMM_SIZE);
    cdg.emit(m_mov, XMM_SIZE, l_reg, 0, t0_result, 0);
    cdg.emit_micro_mvm(mcode_op, op_dtype, l_reg, r_reg, t0_result, 0);
    cdg.emit(m_mov, XMM_SIZE, t0_result, 0, d_reg, 0);
    cdg.mba->free_kreg(t0_result, 16);
    QASSERT(100623, is_xmm_reg(cdg.insn.Op1));
    clear_upper(cdg, d_reg);
    return MERR_OK;
  }

  // VADDPS    xmm1, xmm2, xmm3/m128
  // VADDPS    ymm1, ymm2, ymm3/m256
  merror_t v_math_p(codegen_t &cdg)
  {
    QASSERT(100624, is_avx_reg(cdg.insn.Op1) && is_avx_reg(cdg.insn.Op2));
    int op_size = YMM_SIZE;
    if (is_xmm_reg(cdg.insn.Op1))
      op_size = XMM_SIZE;
    mreg_t r_reg;
    if (is_mem_op(cdg.insn.Op3)) {
      // op3 -- m128/m256
      r_reg = cdg.load_operand(2);
    } else {
      // op3 -- xmm3/ymm3
      QASSERT(100626, is_avx_reg(cdg.insn.Op3));
      r_reg = reg2mreg(cdg.insn.Op3.reg);
    }
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmm1/ymm1
    const char* fmt = NULL;
    bool iType = false;
    switch (cdg.insn.itype) {
    case NN_vaddps: fmt = "_mm%s_add_ps";break;
    case NN_vsubps: fmt = "_mm%s_sub_ps";break;
    case NN_vmulps: fmt = "_mm%s_mul_ps";break;
    case NN_vdivps: fmt = "_mm%s_div_ps";break;
    case NN_vaddpd: fmt = "_mm%s_add_pd"; break;
    case NN_vsubpd: fmt = "_mm%s_sub_pd"; break;
    case NN_vmulpd: fmt = "_mm%s_mul_pd"; break;
    case NN_vdivpd: fmt = "_mm%s_div_pd"; break;
    case NN_vpaddb: fmt = "_mm%s_add_epi8"; iType = true;  break;
    case NN_vpsubb: fmt = "_mm%s_sub_epi8"; iType = true; break;
    case NN_vpaddw: fmt = "_mm%s_add_epi16"; iType = true; break;
    case NN_vpsubw: fmt = "_mm%s_sub_epi16"; iType = true; break;
    case NN_vpaddd: fmt = "_mm%s_add_epi32"; iType = true; break;
    case NN_vpsubd: fmt = "_mm%s_sub_epi32"; iType = true; break;
    case NN_vpaddq: fmt = "_mm%s_add_epi64"; iType = true; break;
    case NN_vpsubq: fmt = "_mm%s_sub_epi64"; iType = true; break;
    default:
      QASSERT(100625,1);
    }

    qstring intrinsic_name;
    intrinsic_name.cat_sprnt(fmt, op_size == YMM_SIZE ? "256" : "");
    AVXIntrinsic avx_intrinsic(&cdg, intrinsic_name.c_str());

    uint32 bit_size = op_size * 8;
    qstring type_name;
    type_name.cat_sprnt("__m%u", bit_size);
    if (iType)
      type_name.append('i');
    tinfo_t op_tinfo;
    op_tinfo.get_named_type(nullptr, type_name.c_str());

    avx_intrinsic.add_argument_reg(reg2mreg(cdg.insn.Op2.reg), op_tinfo);
    avx_intrinsic.add_argument_reg(r_reg, op_tinfo);
    avx_intrinsic.set_return_reg(d_reg, op_tinfo);
    avx_intrinsic.emit();
    if (op_size == XMM_SIZE)
      clear_upper(cdg, d_reg);
    return MERR_OK;
  }

    //-------------------------------------------------------------------------
    // Misc Instructions
    //-------------------------------------------------------------------------

  // VSQRTSS xmm1, xmm2, xmm3/m32
  merror_t vsqrtss(codegen_t &cdg)
  {
    QASSERT(100627, is_xmm_reg(cdg.insn.Op1) && is_xmm_reg(cdg.insn.Op2));
    mreg_t r_reg;
    if (is_xmm_reg(cdg.insn.Op3)) {
      // op3 -- xmm3
      r_reg = reg2mreg(cdg.insn.Op3.reg);
    } else {
      // op3 -- m32
      QASSERT(100628, is_mem_op(cdg.insn.Op3));
      r_reg = cdg.load_operand(2);
    }
    mreg_t l_reg = reg2mreg(cdg.insn.Op2.reg); // op2 - xmm2
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 - xmm1
    mreg_t t0_result = cdg.mba->alloc_kreg(XMM_SIZE);
    cdg.emit(m_mov, XMM_SIZE, l_reg, 0, t0_result, 0);

    // mov.fpu call !fsqrt<fast:float xmm1_4.4>.4, t0_result_4.4
    AVXIntrinsic avx_intrinsic(&cdg, "fsqrt");
    avx_intrinsic.add_argument_reg(r_reg, BT_FLOAT);
    avx_intrinsic.set_return_reg_basic(t0_result, BT_FLOAT);
    avx_intrinsic.emit();

    cdg.emit(m_mov, XMM_SIZE, t0_result, 0, d_reg, 0);
    cdg.mba->free_kreg(t0_result, XMM_SIZE);
    clear_upper(cdg, d_reg);
    return MERR_OK;
  }

  // VSQRTPS xmm1, xmm2/m128
  // VSQRTPS ymm1, ymm2/m256
  merror_t vsqrtps(codegen_t &cdg)
  {
    int op_size = YMM_SIZE;
    if (is_xmm_reg(cdg.insn.Op1))
      op_size = XMM_SIZE;
    mreg_t r_reg;
    if (is_mem_op(cdg.insn.Op2)) {
      // op2 -- m128/m256
      r_reg = cdg.load_operand(1);
    } else {
      // op2 -- xmm2/ymm2
      QASSERT(100629, is_avx_reg(cdg.insn.Op2));
      r_reg = reg2mreg(cdg.insn.Op2.reg);
    }
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmm1/ymm1

    // intrinsic: __m256 _mm256_cvtepi32_ps (__m256i a)
    qstring intrinsic_name;
    intrinsic_name.cat_sprnt("_mm%s_sqrt_ps", op_size == YMM_SIZE ? "256" : "");
    AVXIntrinsic avx_intrinsic(&cdg, intrinsic_name.c_str());
    uint32 bit_size = op_size * 8;
    qstring type_name;
    type_name.cat_sprnt("__m%u", bit_size);
    tinfo_t op_tinfo;
    op_tinfo.get_named_type(nullptr, type_name.c_str());

    avx_intrinsic.add_argument_reg(r_reg, op_tinfo);
    avx_intrinsic.set_return_reg(d_reg, op_tinfo);
    avx_intrinsic.emit();
    if (op_size == XMM_SIZE)
      clear_upper(cdg, d_reg);
    return MERR_OK;
  }

  // VSHUFPS xmm1, xmm2, xmm3/m128, imm8
  // VSHUFPS ymm1, ymm2, ymm3/m256, imm8
  merror_t vshufps(codegen_t &cdg)
  {
    int op_size = YMM_SIZE;
    if (is_xmm_reg(cdg.insn.Op1))
      op_size = XMM_SIZE;
    QASSERT(100630, cdg.insn.Op4.type == o_imm);
    uval_t mask_value = cdg.insn.Op4.value; // op4 -- imm8
    mreg_t r_reg;
    if (is_mem_op(cdg.insn.Op3)) {
      // op3 -- m128/m256
      r_reg = cdg.load_operand(2);
    } else {
      // op3 -- xmm3/ymm3
      QASSERT(100631, is_avx_reg(cdg.insn.Op3));
      r_reg = reg2mreg(cdg.insn.Op3.reg);
    }
    mreg_t l_reg = reg2mreg(cdg.insn.Op2.reg); // op2 -- xmm2/ymm2
    mreg_t d_reg = reg2mreg(cdg.insn.Op1.reg); // op1 -- xmm1/ymm1

    // intrinsics:
    //   __m128 _mm_shuffle_ps (__m128 a, __m128 b, unsigned int imm8)
    //   __m256 _mm256_shuffle_ps (__m256 a, __m256 b, const int imm8)
    qstring intrinsic_name;
    intrinsic_name.cat_sprnt("_mm%s_shuffle_ps", op_size == YMM_SIZE ? "256" : "");
    AVXIntrinsic avx_intrinsic(&cdg, intrinsic_name.c_str());
    uint32 bit_size = op_size * 8;
    qstring type_name;
    type_name.cat_sprnt("__m%u", bit_size);
    tinfo_t op_tinfo;
    op_tinfo.get_named_type(nullptr, type_name.c_str());

    avx_intrinsic.add_argument_reg(l_reg, op_tinfo);
    avx_intrinsic.add_argument_reg(r_reg, op_tinfo);
    avx_intrinsic.add_argument_imm(mask_value, BT_INT8);
    avx_intrinsic.set_return_reg(d_reg, op_tinfo);
    avx_intrinsic.emit();
    if (op_size == XMM_SIZE)
      clear_upper(cdg, d_reg);
    return MERR_OK;
  }
};

bool isMicroAvx_avail()
{
  if (PH.id != PLFM_386 || !inf_is_64bit())
    return false;
  return true;
}

static AVXLifter* avx = nullptr;
bool isMicroAvx_active()
{
  return avx != nullptr;
}
void MicroAvx_init()
{
  avx = new AVXLifter();
  install_microcode_filter(avx);
};

void MicroAvx_done()
{
  if(avx) {
    install_microcode_filter(avx, false);
    delete avx;
    avx = nullptr;
  }
}
#endif //IDA_SDK_VERSION >= 750
