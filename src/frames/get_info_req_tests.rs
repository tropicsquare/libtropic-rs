#[cfg(test)]

mod unit {
    use crate::frames::{get_info_req::GetInfoReqFrame, *};

    #[test]
    fn can_be_constructed() {
        let get_info_req_frame = GetInfoReqFrame {
            data: get_info_req::ReqData::ChipID,
        };

        println!("{:#?}", get_info_req_frame);
    }
}
