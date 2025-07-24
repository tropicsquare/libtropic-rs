use embedded_hal::digital::ErrorType as GpioErrorType;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::ErrorType as SpiErrorType;
use embedded_hal::spi::Operation;
use embedded_hal::spi::SpiDevice;
use packed_struct::PackedStruct as _;

use super::Error;
use crate::ChipStatus;
use crate::L1_READ_MAX_TRIES;
use crate::L2_CMD_REQ_LEN;

const L2_CMD_ID_GET_RESPONSE: u8 = 0xaa;

pub(super) fn l1_read<SPI: SpiDevice, CS: OutputPin>(
    l2_buf: &mut [u8],
    spi: &mut SPI,
    cs: &mut Option<CS>,
) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
    for _ in 0..L1_READ_MAX_TRIES {
        l2_buf.fill(0);
        l2_buf[0] = L2_CMD_ID_GET_RESPONSE;
        l2_buf[1] = L2_CMD_REQ_LEN as u8;
        l1_transfer(l2_buf, spi, cs)?;

        match ChipStatus::unpack(&[l2_buf[0]]) {
            Ok(status) if status.alarm => return Err(Error::AlarmMode),
            // chip status is ready and response status is not `NO_RESP` (0xff)
            Ok(status) if status.ready && l2_buf[1] != 0xff => {
                return Ok(());
            },
            Ok(_) => l1_delay_ns(spi, cs, 25_000_000)?,
            Err(err) => return Err(Error::InvalidChipStatus(err)),
        }
    }

    Err(Error::ChipBusy)
}

pub(super) fn l1_write<SPI: SpiDevice, CS: OutputPin>(
    l2_buf: &mut [u8],
    spi: &mut SPI,
    cs: &mut Option<CS>,
) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
    for _ in 0..L1_READ_MAX_TRIES {
        l1_transfer(l2_buf, spi, cs)?;

        match ChipStatus::unpack(&[l2_buf[0]]) {
            Ok(status) if status.alarm => return Err(Error::AlarmMode),
            Ok(status) if status.ready => {
                return Ok(());
            },
            Ok(_) => l1_delay_ns(spi, cs, 25_000_000)?,
            Err(err) => return Err(Error::InvalidChipStatus(err)),
        }
    }

    Ok(())
}

/// Delay for `ns` nanoseconds.
pub(super) fn l1_delay_ns<SPI: SpiDevice, CS: OutputPin>(
    spi: &mut SPI,
    _cs: &mut Option<CS>,
    ns: u32,
) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
    spi.transaction(&mut [Operation::DelayNs(ns)])
        .map_err(Error::BusError)
}

fn l1_transfer<SPI: SpiDevice, CS: OutputPin>(
    l2_buf: &mut [u8],
    spi: &mut SPI,
    cs: &mut Option<CS>,
) -> Result<(), Error<<SPI as SpiErrorType>::Error, <CS as GpioErrorType>::Error>> {
    if let Some(cs) = cs {
        cs.set_low().map_err(Error::GPIOError)?;
    }
    let res = spi.transaction(&mut [Operation::TransferInPlace(&mut l2_buf[..])]);
    if let Some(cs) = cs {
        cs.set_high().map_err(Error::GPIOError)?;
    }
    res.map_err(Error::BusError)?;
    Ok(())
}
