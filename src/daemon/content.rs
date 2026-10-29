//! Additional machine-readable message content. Existing display fields stay intact.
use serde_json::{json, Value};
fn text(node: roxmltree::Node<'_, '_>, tag: &str) -> String {
    node.descendants()
        .find(|n| n.has_tag_name(tag))
        .and_then(|n| n.text())
        .unwrap_or("")
        .to_owned()
}
fn fields(node: roxmltree::Node<'_, '_>, tags: &[&str]) -> Value {
    let mut out = serde_json::Map::new();
    for tag in tags {
        let value = text(node, tag);
        if !value.is_empty() {
            out.insert((*tag).into(), json!(value));
        }
    }
    Value::Object(out)
}
fn attributes(node: roxmltree::Node<'_, '_>, names: &[&str]) -> Value {
    let mut out = serde_json::Map::new();
    for name in names {
        if let Some(v) = node.attribute(*name) {
            out.insert((*name).into(), json!(v));
        }
    }
    Value::Object(out)
}
pub fn details(local_type: i64, content: &str) -> Value {
    let base = local_type as u64 & 0xffffffff;
    if base == 1 {
        return json!({"kind":"text","text":content});
    }
    // A persisted revoke notice is a plain system message on Linux. Preserve
    // the notice; it does not contain the original, withdrawn message body.
    if base == 10000 {
        return json!({"kind":"system","text":content});
    }
    let start = content.find('<').unwrap_or(0);
    let Ok(doc) = roxmltree::Document::parse(&content[start..]) else {
        return json!({"kind":"unparsed","base_type":base});
    };
    let root = doc.root_element();
    match base {
        3 => root.descendants().find(|n|n.has_tag_name("img")).map(|n|json!({"kind":"image","metadata":attributes(n,&["md5","length","width","height","cdnthumbwidth","cdnthumbheight"])})),
        43 => root.descendants().find(|n|n.has_tag_name("videomsg")).map(|n|json!({"kind":"video","metadata":attributes(n,&["md5","length","playlength","cdnthumbwidth","cdnthumbheight","cdnvideourl"])})),
        47 => root.descendants().find(|n|n.has_tag_name("emoji")).map(|n|json!({"kind":"sticker","metadata":attributes(n,&["md5","len","width","height","cdnurl","thumburl"]),"local_decode":"unverified"})),
        42 => Some(json!({"kind":"contact_card","metadata":attributes(root,&["username","nickname","alias","province","city","sign","sex","bigheadimgurl","smallheadimgurl"])})),
        34 => root.descendants().find(|n|n.has_tag_name("voicemsg")).map(|n|json!({"kind":"voice","metadata":attributes(n,&["voicelength","length","voiceformat","bufid"])})),
        48 => root.descendants().find(|n|n.has_tag_name("location")).map(|n|json!({"kind":"location","metadata":attributes(n,&["x","y","scale","label","poiname"])})),
        49 => {
            let Some(app)=root.descendants().find(|n|n.has_tag_name("appmsg")) else { return json!({"kind":"unparsed","base_type":base}); };
            let subtype=text(app,"type").parse::<u64>().unwrap_or(0);
            let high=(local_type as u64)>>32;
            let mut result=json!({"kind":"appmsg","subtype":subtype,"subtype_consistent":high==0 || high==subtype,"title":text(app,"title")});
            match subtype {
                6 => { result["kind"]=json!("file");result["metadata"]=fields(app,&["fileext","totallen","md5","attachid"]); }
                5 => { result["kind"]=json!("article");result["metadata"]=fields(app,&["url","sourcedisplayname","sourceusername","des"]); }
                51 => { result["kind"]=json!("finder"); if let Some(feed)=app.descendants().find(|n|n.has_tag_name("finderFeed")) { result["metadata"]=fields(feed,&["nickname","username","desc","objectId","objectNonceId","mediaType","url","coverUrl","videoPlayDuration","duration","width","height"]); } }
                19 => {
                    result["kind"]=json!("forwarded_record");
                    let record=text(app,"recorditem");
                    if let Ok(record)=roxmltree::Document::parse(&record) {
                        let items:Vec<_>=record.descendants().filter(|n|n.has_tag_name("dataitem")).take(1000).map(|n|json!({"datatype":n.attribute("datatype"),"content":fields(n,&["datadesc","datatitle","sourcename","sourcetime","sourceheadurl","fromusr","realchatname"])})).collect();
                        result["items"]=json!(items);
                        result["declared_count"]=record.descendants().find(|n|n.has_tag_name("datalist")).and_then(|n|n.attribute("count")).map(|s|json!(s)).unwrap_or(Value::Null);
                    } else { result["parse_status"]=json!("invalid_record_xml"); }
                }
                57 => { result["kind"]=json!("quote"); if let Some(reference)=app.descendants().find(|n|n.has_tag_name("refermsg")) { result["reference"]=fields(reference,&["type","svrid","fromusr","chatusr","displayname","content","createtime"]); } }
                33|36 => { result["kind"]=json!("mini_program"); result["metadata"]=fields(app,&["url","username","appid","pagepath","weappiconurl"]); }
                _ => { result["metadata"]=fields(app,&["url","des"]); }
            }
            Some(result)
        }
        _ => None,
    }.unwrap_or_else(||json!({"kind":"unparsed","base_type":base}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_system_notice_is_preserved() {
        let notice = "测试用户撤回了一条消息";
        assert_eq!(
            details(10000, notice),
            json!({"kind":"system","text":notice})
        );
    }

    #[test]
    fn finder_uses_feed_link_and_complete_record_text() {
        let d=details((51i64<<32)|49,"<msg><appmsg><type>51</type><url>help</url><finderFeed><url>media</url><desc>full</desc></finderFeed></appmsg></msg>");
        assert_eq!(d["metadata"]["url"], "media");
        assert_eq!(d["subtype_consistent"], true);
        let d=details(49,"<msg><appmsg><type>19</type><recorditem><![CDATA[<recordinfo><datalist count=\"1\"><dataitem datatype=\"1\"><datadesc>complete content</datadesc></dataitem></datalist></recordinfo>]]></recorditem></appmsg></msg>");
        assert_eq!(d["items"][0]["content"]["datadesc"], "complete content");
    }
}
