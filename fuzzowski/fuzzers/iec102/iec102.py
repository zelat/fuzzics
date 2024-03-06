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

    @staticmethod
    def get_requests() -> List[callable]:
        return [IEC102.iec102_start]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:
        s_initialize("iec102_start")
        with s_block("iec_frame"):
            s_byte(0x10, name="start", fuzzable=False)               # 帧起始符
            s_byte(0x53, name="control_field", fuzzable=True)        # 控制字段
            s_word(0x0001, name="address_field", fuzzable=True)      # 地址字段
            s_dword(0x00000000, name="link_user_data", fuzzable=True)  # 链路用户数据
            s_byte(0x00, name="checksum", fuzzable=False)             # 占位符
            s_byte(0x16, name="end", fuzzable=False)  # 帧结束符

    # IEC102 Flow
    # -----------------------------------------------
    @staticmethod
    def iec102_start(session: Session) -> None:
        session.connect(s_get('iec102_start'))
