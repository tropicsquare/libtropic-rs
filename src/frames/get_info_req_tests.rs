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

    mod certificate_frame_tests {
        use crate::frames::{get_info_req::GetInfoReqFrame, *};

        #[test]
        fn can_be_constructed() {
            let get_info_req_frame = GetInfoReqFrame {
                data: get_info_req::ReqData::X509Certificate { chunk: 0x00 },
            };

            assert_eq!(
                get_info_req_frame.as_bytes(),
                vec![0x01, 0x02, 0x00, 0x00, 0x28, 0x14]
            );
        }
    }
}
