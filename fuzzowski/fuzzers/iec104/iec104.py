from fuzzowski.fuzzers.ifuzzer import IFuzzer
from fuzzowski.mutants.spike import *
from fuzzowski import *
from fuzzowski import Session


class IEC104(IFuzzer):
    """
       IEC104 Fuzzing Module
       Use at your own risk, and please do not use in a production environment

       Based on https://github.com/M-Kings/ElecFuzz/blob/main/util/iec104.py

       virtualenv venv -p python3
       source venv/bin/activate
       pip install -r requirements.txt

       python -m fuzzowski 10.230.114.63 2045 -p tcp -f IEC104 -r iec104_clock_sync
       python -m fuzzowski 10.230.114.63 2045 -p tcp -f IEC104
       python -m fuzzowski 10.230.114.63 2045 -p tcp -f IEC104 -rt 1 -m iec104Mon
       """

    # --------------------------------------------------------------- #

    name = "IEC104"

    @staticmethod
    def get_requests() -> List[callable]:
        return [IEC104.iec104_startdt, IEC104.iec104_apci_cf, IEC104.iec104_M_SP_NA_1,
                IEC104.iec104_M_DP_NA_1,
                IEC104.iec104_M_ST_NA_1,
                IEC104.iec104_M_BO_NA_1,
                IEC104.iec104_M_ME_NA_1,
                IEC104.iec104_M_ME_NB_1,
                IEC104.iec104_M_ME_NC_1,
                IEC104.iec104_M_IT_NA_1,
                IEC104.iec104_M_PS_NA_1,
                IEC104.iec104_M_ME_ND_1,
                IEC104.iec104_M_SP_TB_1,
                IEC104.iec104_M_DP_TB_1,
                IEC104.iec104_M_ST_TB_1,
                IEC104.iec104_M_BO_TB_1,
                IEC104.iec104_M_ME_TD_1,
                IEC104.iec104_M_ME_TE_1,
                IEC104.iec104_M_ME_TF_1,
                IEC104.iec104_M_IT_TB_1,
                IEC104.iec104_C_SC_NA_1,
                IEC104.iec104_C_DC_NA_1,
                IEC104.iec104_C_SE_NB_1,
                IEC104.iec104_C_SE_NC_1,
                IEC104.iec104_M_EI_NA_1,
                IEC104.iec104_C_CI_NA_1,
                IEC104.iec104_clock_sync, IEC104.iec104_inter_command, IEC104.other_operations]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:
        s_initialize("iec104_startdt")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x04, name="apdu_length", fuzzable=True)
            s_dword(0x07000000, name="type", fuzzable=False)

        s_initialize("iec104_apci_cf")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x04, name="apdu_length", fuzzable=True)
            s_byte(0x01, name="pad1", fuzzable=True)
            s_byte(0x00, name="pad2", fuzzable=True)
            s_byte(0x00, name="pad3", fuzzable=True)
            s_byte(0x00, name="pad4", fuzzable=True)

        s_initialize("iec104_M_SP_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x01, name="type_id", fuzzable=False)  # M_SP_NA_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")  # Fixed CP56Time: Feb 12, 2020

        s_initialize("iec104_M_DP_NA_1")
        with s_block("iec_apci"):
            s_byte(0x03, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x68, name="type_id", fuzzable=False)  # M_DP_NA_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_ST_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x05, name="type_id", fuzzable=False)  # M_ST_NA_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_BO_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x07, name="type_id", fuzzable=False)  # M_BO_NA_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_ME_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x09, name="type_id", fuzzable=False)  # M_ME_NA_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_ME_NB_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x0B, name="type_id", fuzzable=False)  # M_ME_NB_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_ME_NC_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x0D, name="type_id", fuzzable=False)  # M_ME_NC_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_IT_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x0F, name="type_id", fuzzable=False)  # M_ME_NC_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_PS_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x14, name="type_id", fuzzable=False)  # M_ME_NC_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_ME_ND_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x15, name="type_id", fuzzable=False)  # M_ME_ND_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_SP_TB_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x1E, name="type_id", fuzzable=False)  # M_SP_TB_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_DP_TB_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x1F, name="type_id", fuzzable=False)  # M_SP_TB_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_ST_TB_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x20, name="type_id", fuzzable=False)  # M_ST_TB_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_BO_TB_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x21, name="type_id", fuzzable=False)  # M_BO_TB_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_ME_TD_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x22, name="type_id", fuzzable=False)  # M_ME_TD_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_ME_TE_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x23, name="type_id", fuzzable=False)  # M_ME_TE_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_ME_TF_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x24, name="type_id", fuzzable=False)  # M_ME_TF_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_IT_TB_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x25, name="type_id", fuzzable=False)  # M_IT_TB_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_C_SC_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x2D, name="type_id", fuzzable=False)  # C_SC_NA_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_C_DC_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x2E, name="type_id", fuzzable=False)  # C_DC_NA_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_C_SE_NB_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x31, name="type_id", fuzzable=False)  # C_SE_NB_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_C_SE_NC_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x32, name="type_id", fuzzable=False)  # C_SE_NC_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_M_EI_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x46, name="type_id", fuzzable=False)  # M_EI_NA_1  Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_C_CI_NA_1")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x65, name="type_id", fuzzable=False)  # C_IC_NA_1  Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")

        s_initialize("iec104_clock_sync")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x14, name="apdu_length", fuzzable=True)
            s_dword(0x000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x67, name="type_id", fuzzable=False)  # C_CS_NA_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)  # T-P/N-COT (1-1-6 bit)
                s_byte(0x00, name="org", fuzzable=False)  # Originator Address
                s_word(0xffff, name="com", fuzzable=True)  # Common Address of ASDU
                if s_block("iec_ioa"):  # Information Object
                    s_byte(0x67, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x67, name="ioa_2", fuzzable=True)
                    s_byte(0x67, name="ioa_3", fuzzable=True)
                    s_static("\xee\xd8\x09\x0c\x0c\x02\x14")  # Fixed CP56Time: Feb 12, 2020

        s_initialize("iec104_inter_command")
        with s_block("iec_apci"):
            s_byte(0x68, name="start", fuzzable=False)
            s_byte(0x0e, name="apdu_length", fuzzable=True)
            s_dword(0x02000000, name="type", fuzzable=False)
            if s_block("iec_asdu"):
                s_byte(0x64, name="type_id", fuzzable=False)  # C_IC_NA_1 Act
                s_byte(0x01, name="sq_plus_no", fuzzable=True)  # A-BBBBBBB (1-7 bit)
                s_byte(0x06, name="cot", fuzzable=True)
                s_byte(0x00, name="org", fuzzable=False)
                s_word(0xffff, name="com", fuzzable=True)
                if s_block("iec_ioa"):
                    s_byte(0x00, name="ioa_1", fuzzable=True)  # IOA: 3-byte length
                    s_byte(0x00, name="ioa_2", fuzzable=True)
                    s_byte(0x00, name="ioa_3", fuzzable=True)
                    s_byte(0x14, name="qoi", fuzzable=True)

    # IEC104 Flow
    # -----------------------------------------------
    # STARTDT act ->
    # STARTDT con <-
    # C_CS_NA_1 Act (Clock syncronization command) ->
    # C_IC_NA_1 Act (Interrogation command) ->
    # M_EI_NA_1 Init (End of initialization) <-
    # M_SP_NA_1 Spont (Single-point information) <-
    # C_CI_NA_1 Act ->
    # C_IC_NA_1 ActCon <-
    @staticmethod
    def iec104_startdt(session: Session) -> None:
        session.connect(s_get('iec104_startdt'))

    @staticmethod
    def iec104_apci_cf(session: Session) -> None:
        session.connect(s_get('iec104_apci_cf'))

    @staticmethod
    def iec104_M_SP_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_M_SP_NA_1'))

    @staticmethod
    def iec104_M_DP_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_M_DP_NA_1'))

    @staticmethod
    def iec104_M_ST_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_M_ST_NA_1'))

    @staticmethod
    def iec104_M_BO_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_M_BO_NA_1'))

    @staticmethod
    def iec104_M_ME_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_M_ME_NA_1'))

    @staticmethod
    def iec104_M_ME_NB_1(session: Session) -> None:
        session.connect(s_get('iec104_M_ME_NA_1'))

    @staticmethod
    def iec104_M_ME_NC_1(session: Session) -> None:
        session.connect(s_get('iec104_M_ME_NA_1'))

    @staticmethod
    def iec104_M_IT_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_M_IT_NA_1'))

    @staticmethod
    def iec104_M_PS_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_M_PS_NA_1'))

    @staticmethod
    def iec104_M_ME_ND_1(session: Session) -> None:
        session.connect(s_get('iec104_M_ME_ND_1'))

    @staticmethod
    def iec104_M_DP_TB_1(session: Session) -> None:
        session.connect(s_get('iec104_M_DP_TB_1'))

    @staticmethod
    def iec104_M_SP_TB_1(session: Session) -> None:
        session.connect(s_get('iec104_M_SP_TB_1'))

    @staticmethod
    def iec104_M_ST_TB_1(session: Session) -> None:
        session.connect(s_get('iec104_M_SP_TB_1'))

    @staticmethod
    def iec104_M_BO_TB_1(session: Session) -> None:
        session.connect(s_get('iec104_M_BO_TB_1'))

    @staticmethod
    def iec104_M_ME_TD_1(session: Session) -> None:
        session.connect(s_get('iec104_M_ME_TD_1'))

    @staticmethod
    def iec104_M_ME_TF_1(session: Session) -> None:
        session.connect(s_get('iec104_M_ME_TF_1'))

    @staticmethod
    def iec104_M_IT_TB_1(session: Session) -> None:
        session.connect(s_get('iec104_M_IT_TB_1'))

    @staticmethod
    def iec104_M_ME_TE_1(session: Session) -> None:
        session.connect(s_get('iec104_M_ME_TE_1'))

    @staticmethod
    def iec104_C_SC_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_C_SC_NA_1'))

    @staticmethod
    def iec104_C_DC_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_C_DC_NA_1'))

    @staticmethod
    def iec104_C_SE_NB_1(session: Session) -> None:
        session.connect(s_get('iec104_C_SE_NB_1'))

    @staticmethod
    def iec104_C_SE_NC_1(session: Session) -> None:
        session.connect(s_get('iec104_C_SE_NC_1'))

    @staticmethod
    def iec104_M_EI_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_M_EI_NA_1'))

    @staticmethod
    def iec104_C_CI_NA_1(session: Session) -> None:
        session.connect(s_get('iec104_C_CI_NA_1'))

    @staticmethod
    def iec104_clock_sync(session: Session) -> None:
        session.connect(s_get('iec104_clock_sync'))

    @staticmethod
    def iec104_inter_command(session: Session) -> None:
        session.connect(s_get('iec104_inter_command'))

    @staticmethod
    def other_operations(session: Session) -> None:
        session.connect(s_get('iec104_startdt'))
        session.connect(s_get('iec104_startdt'), s_get("iec104_clock_sync"))
        session.connect(s_get("iec104_clock_sync"), s_get("iec104_inter_command"))
