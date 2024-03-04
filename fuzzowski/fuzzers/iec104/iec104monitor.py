from fuzzowski.monitors.imonitor import IMonitor
from fuzzowski.connections import ITargetConnection

class IEC104Monitor(IMonitor):

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
            data = conn.recv_all(10000)
            if len(data) == 0:
                self.logger.log_error("MODBUS error response, getting MODBUS device information Failed!!")
                result = False
            else:
                Unit_ID = data[6].to_bytes((data[6].bit_length() + 7) // 8, byteorder='big')
                Func_code = data[7]
                Exception_code = data[8]

                if data[5] > 0:
                    if hex(Func_code) == '0x11':
                      self.logger.log_info(f"Getting IEC104 device information succeeded")
                    elif hex(Exception_code) == '0xb':
                      self.logger.log_warn(f"Getting IEC104 device information: Gateway target device failed to respond")
                    elif hex(Exception_code) == '0x1':
                      self.logger.log_warn(f"Getting IEC104 device information: Illegal function")
                    else:
                      self.logger.log_warn(f"Getting IEC104 device information warning")
                else:
                  self.logger.log_warn(f"Getting IEC104 data error")

                result = True
        except Exception as e:
            self.logger.log_error(f"IEC104 response error, getting IEC104 device information Failed!! Exception while receiving: {type(e).__name__}. {str(e)}")
            result = False
        finally:
            conn.close()

        return result