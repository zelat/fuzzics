from fuzzowski.monitors.imonitor import IMonitor
from fuzzowski.connections import ITargetConnection


class IEC104Monitor(IMonitor):
    # \x68\x04\x07\x00\x00\x00
    # Send Read Device Identification (读取设备ID)
    get_iec104_nse = (b"\x68"  # 启动字符
                      b"\x04"  # APCI长度
                      b"\x07\x00\x00\x00"  # 控制字段
                      )

    @staticmethod
    def name() -> str:
        return "iec104Mon"

    @staticmethod
    def help():
        return "Sends a query for IEC104 device id to the target and check the response"

    def test(self):
        conn = self.get_connection_copy()
        result = self._get_iec104_info(conn)
        return result

    def _get_iec104_info(self, conn: ITargetConnection):
        try:
            conn.open()
            conn.send(self.get_iec104_nse)
            data = conn.recv_all(10000)
            if len(data) == 0:
                self.logger.log_error("IEC104 error response, getting IEC104 device information Failed!!")
                result = False
            else:
                self.logger.log_info(''.join(['{:02x}'.format(byte) for byte in data]))
                Start_code = data[0]
                APDU_len_code = data[1]
                if hex(Start_code) == '0x68' and hex(APDU_len_code) == '0x04':
                    self.logger.log_info(f"Getting IEC104 device information succeeded")
                result = True
        except Exception as e:
            self.logger.log_error(
                f"IEC104 response error, getting IEC104 device information Failed!! Exception while receiving: {type(e).__name__}. {str(e)}")
            result = False
        finally:
            conn.close()

        return result
