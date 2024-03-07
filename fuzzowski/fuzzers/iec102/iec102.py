from fuzzowski.fuzzers.ifuzzer import IFuzzer
from fuzzowski.mutants.spike import *
from fuzzowski import *
from fuzzowski import Session

class IEC102(IFuzzer):
    """
       IEC102 Fuzzing Module
       Use at your own risk, and please do not use in a production environment

       Based on https://github.com/M-Kings/ElecFuzz/blob/main/util/iec102.py

       virtualenv venv -p python3
       source venv/bin/activate
       pip install -r requirements.txt

       python -m fuzzowski 10.230.114.63 2047 -p tcp -f IEC102 -r iec102_start   # 测试IEC102起始帧
       python -m fuzzowski 10.230.114.63 2047 -p tcp -f IEC102
       python -m fuzzowski 10.230.114.63 2047 -p tcp -f IEC102 -rt 1 -m iec102Mon
       """

    # --------------------------------------------------------------- #

    name = "IEC102"

    def calc_iec102_checksum(self, frame):
        # 移除起始字符、长度地段、校验和占位符和结束字段，只保留计算校验和的部分
        checksum_part = frame[4:-4]
        checksum = 0
        for i in range(0, len(checksum_part), 2):
            byte = int (checksum_part[i:i+2], 16)
            checksum += byte
        checksum %= 256
        return checksum


    @staticmethod
    def get_requests() -> List[callable]:
        return [IEC102.iec102_start]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:
        s_initialize("iec102_lpci")
        with s_block("iec102_lpci"):
            s_byte(0x68, name="start", fuzzable=False)           # start field
            s_byte(0x14, name="length", fuzzable=False)
            s_byte(0x08, name="control", fuzzable=True)          # Control field
            s_word(0x0001, name="address", fuzzable=True)        # Address field
            if s_block("iec102_asdu"):
                s_byte(0x01, name="type_id", fuzzable=False)     # Type Indentification
                s_byte(0x01, name="sq_plus_no", fuzzable=False)
                s_byte(0x02, name="cot", fuzzable=True)
                s_word(0x0001, name="asdu_addr", fuzzable=True)
                s_word(0x04D2, name="infor_obj", fuzzable=False)
                s_word(0x04D2, name="checksum", fuzzable=False)
                s_byte(0x16, name="end", fuzzable=False)        # end field

    # IEC102 Flow
    # -----------------------------------------------
    @staticmethod
    def iec102_start(session: Session) -> None:
        session.connect(s_get('iec102_start'))
