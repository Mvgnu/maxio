use crate::error::S3Error;

const MIN_PART_NUMBER: u32 = 1;
const MAX_PART_NUMBER: u32 = 10_000;

pub(super) fn parse_part_number(raw: &str) -> Result<u32, S3Error> {
    let part_number = raw
        .parse::<u32>()
        .map_err(|_| S3Error::invalid_part("invalid part number"))?;
    if !(MIN_PART_NUMBER..=MAX_PART_NUMBER).contains(&part_number) {
        return Err(S3Error::invalid_part(
            "part number must be between 1 and 10000",
        ));
    }
    Ok(part_number)
}

pub(super) fn parse_complete_parts(xml: &str) -> Result<Vec<(u32, String)>, S3Error> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut parts = Vec::new();
    let mut in_part = false;
    let mut in_part_number = false;
    let mut in_etag = false;
    let mut part_number: Option<u32> = None;
    let mut etag: Option<String> = None;
    let mut previous_part_number: Option<u32> = None;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) => match e.name().as_ref() {
                b"Part" => {
                    in_part = true;
                    part_number = None;
                    etag = None;
                }
                b"PartNumber" if in_part => in_part_number = true,
                b"ETag" if in_part => in_etag = true,
                _ => {}
            },
            Ok(quick_xml::events::Event::Text(e)) => {
                if in_part_number {
                    let value = e
                        .unescape()
                        .map_err(|_| S3Error::malformed_xml())?
                        .into_owned();
                    part_number = Some(parse_part_number(&value)?);
                    in_part_number = false;
                } else if in_etag {
                    let value = e
                        .unescape()
                        .map_err(|_| S3Error::malformed_xml())?
                        .into_owned();
                    let normalized = if value.starts_with('"') && value.ends_with('"') {
                        value
                    } else {
                        format!("\"{}\"", value)
                    };
                    etag = Some(normalized);
                    in_etag = false;
                }
            }
            Ok(quick_xml::events::Event::End(e)) => match e.name().as_ref() {
                b"PartNumber" => in_part_number = false,
                b"ETag" => in_etag = false,
                b"Part" => {
                    let current_part = part_number.ok_or_else(S3Error::malformed_xml)?;
                    if let Some(previous_part) = previous_part_number {
                        if current_part <= previous_part {
                            return Err(S3Error::invalid_part(
                                "parts must be in strictly ascending part-number order",
                            ));
                        }
                    }
                    let tag = etag.clone().ok_or_else(S3Error::malformed_xml)?;
                    parts.push((current_part, tag));
                    previous_part_number = Some(current_part);
                    in_part = false;
                }
                _ => {}
            },
            Ok(quick_xml::events::Event::Eof) => {
                if in_part || in_part_number || in_etag {
                    return Err(S3Error::malformed_xml());
                }
                break;
            }
            Err(_) => return Err(S3Error::malformed_xml()),
            _ => {}
        }
    }

    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_part_number_accepts_bounds() {
        assert_eq!(parse_part_number("1").unwrap(), 1);
        assert_eq!(parse_part_number("10000").unwrap(), 10_000);
    }

    #[test]
    fn parse_part_number_rejects_out_of_range_and_invalid() {
        assert!(parse_part_number("0").is_err());
        assert!(parse_part_number("10001").is_err());
        assert!(parse_part_number("abc").is_err());
    }

    #[test]
    fn parse_complete_parts_normalizes_etags() {
        let xml = r#"
            <CompleteMultipartUpload>
                <Part><PartNumber>1</PartNumber><ETag>abc</ETag></Part>
                <Part><PartNumber>2</PartNumber><ETag>"def"</ETag></Part>
            </CompleteMultipartUpload>
        "#;
        let parts = parse_complete_parts(xml).unwrap();
        assert_eq!(
            parts,
            vec![(1, "\"abc\"".to_string()), (2, "\"def\"".to_string())]
        );
    }

    #[test]
    fn parse_complete_parts_rejects_non_ascending_parts() {
        let xml = r#"
            <CompleteMultipartUpload>
                <Part><PartNumber>2</PartNumber><ETag>"a"</ETag></Part>
                <Part><PartNumber>1</PartNumber><ETag>"b"</ETag></Part>
            </CompleteMultipartUpload>
        "#;
        assert!(parse_complete_parts(xml).is_err());
    }

    #[test]
    fn parse_complete_parts_rejects_missing_fields_and_malformed_xml() {
        let missing_number = r#"
            <CompleteMultipartUpload>
                <Part><ETag>"a"</ETag></Part>
            </CompleteMultipartUpload>
        "#;
        assert!(parse_complete_parts(missing_number).is_err());

        let missing_etag = r#"
            <CompleteMultipartUpload>
                <Part><PartNumber>1</PartNumber></Part>
            </CompleteMultipartUpload>
        "#;
        assert!(parse_complete_parts(missing_etag).is_err());

        assert!(parse_complete_parts("<CompleteMultipartUpload><Part>").is_err());
    }
}
