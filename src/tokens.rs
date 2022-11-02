use jwt::algorithm::openssl::PKeyWithDigest;
use jwt::{header::HeaderType, AlgorithmType, Header, SignWithKey, Token};
use nbroutes_util::timestamp;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use serde_json::value::{Map, Number, Value};

const PRIVATE_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAh9HF/T5KVhvVoHkFv/JezlJUinikLR86GgNWrX3aO6uXJDI7
OYXAOZWgh4RUDs/vch6mmG9UdlkhU86kot8LDVF0AgBQXFa7nk/AIJTEHKS88URe
o03X3aM5RSoQ2EZLSbskbS4RVurSFJ+NENBhFKcmEy3pJ+6/iKvaUJI7H7i4n2m1
EK6N286w1ZpG9XbuG3cDm3eA/rBtBaUeTzAwwKz+diADUBSJbGy2vokesTZ+85oh
eNX5jSwJDN+Q/m5zYL9krNXTrl8eQkfwps/4PRjoz8JJuB4fTeDxA9bxQZRFGwud
0M2L2xUK0Jf52mO4Mu7WRpIWK41SrHhI9m4vqQIDAQABAoIBACTfTmDyCDxYUia+
tFDn+9UHhOwS1H9retqVDXMMN7L7YozxFiMHrKf1dx9TTX639MmGiLPZhZSbnfCi
qQ+OffGfq17ftvFampTgEcjGmncsQh898HNlLrV9Go8sXGZarxXVOI5rc0mldmMi
7aki6TgyKKQMUsAEkPsJrLsy99okYZwgqzGkftD+PkeJyVaJh07kx1v8mAuMtkJ0
jgDkQQvbpDgQbECpHRMz1YFrkn1LpvrIZCUkoVQEgtQ20g0ggR9waBwAl+JiZX6X
NyVcw176MeOATelA7ezP7A0yIPUquRvGR+wo0aQEaEyF/nvsQgtih50TgYLgNNfh
PyuowAECgYEA//qoBx/0CqahiJ06RwNiX3zJbHStYfpi6JHibpbrCOBqN/VpfOOS
paOMsfAqkstczvJjOFnqY9OJNCpIyXVIkmbUUvQy67B+6rQ1l1XhBtCBJollbhFK
vPsE6NQ3kK3WhhiCWbp287PE9GSTDyugEQmg/Cwcl0pjd2YTLfmQ0XkCgYEAh9Sb
0Zct2BQRT7vxQNyhBQ9PV5nXL3mk+S8AJb3+OK4fF0FWO5aPRl67hPXzcJrTo/Dg
00knWQ3PoApHCNw4F07Yixi9yRmVf4MRk2E48mgGBRISelzxcGY6hezi22hK5Kv7
3DmM9PnfkKc1kGkVo5kfiRKzrJnFmgHu5zvUc7ECgYEAugBj+hFg3iBofgFpaFJw
N9xP7Gv31JsBJedjdmJZVLDk3daImUQvugZWZLGT7eixfnqoWDkV1QXPy8Tx8Nk1
K5RmsgRZv+MWxeq+ikHP6oi1X9A0kL8l5J4t2hTib1Gx8Ox8Q0D30GuPMNqn9T0I
6XhqrvJKsDBQiGD2jNCsR1kCgYA/YjEMDtXvvP2PDY64y7u/1rMZl8pYdxVKymnx
MsWMwYP0oCKTT+Cv38j1dKgS5czY9bCUJ9Dat50pe2JGei0ag0p9LiBx1SR0Cj+L
XJTsWSpl91b0DqcD4lBw6me6JuK77p1q2Ng0AN4YbE6Mgtz8KJoUpst9QYx6H2jS
MpMjIQKBgEQj6sSuvtcbSqtimp+uK3xy+EAlaKqSsOwu8R7sO6x28fA1dWyJfNmG
IhkH7sjO+0mSxavtDv71MiHT5Oo7VEkVzhias51jGtcqxtOk/plwCsiDQ+vytz7i
J6rjH/mt+rADVC4hZhCceedj3a529cJ8RUfpH0tdTUIqJovpE7Wa
-----END RSA PRIVATE KEY-----"#;

// pub fn sign_jwts(conf: &Config) -> HashMap<String, String> {
//     let mut res = HashMap::new();
//     for (aud, cluster) in conf.aud_cluster_map.iter() {
//         res.insert(cluster.clone(), sign_jwt(aud.as_str()));
//     }
//
//     res
// }

pub fn sign_jwt(auds: Vec<String>) -> String {
    let kk = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: PKey::private_key_from_pem(PRIVATE_PEM.as_bytes()).unwrap(),
    };

    let header = Header {
        algorithm: AlgorithmType::Rs256,
        key_id: Some("nb.ai".to_string()),
        type_: Some(HeaderType::JsonWebToken),
        ..Default::default()
    };

    let mut xmap = Map::new();
    xmap.insert(
        "exp".to_owned(),
        Value::Number(Number::from(timestamp() + 48 * 3600 as i64)),
    );

    let mut json_auds = vec![];
    for aud in auds {
        json_auds.push(Value::String(aud));
    }
    xmap.insert("aud".to_owned(), Value::Array(json_auds));
    let claims: Value = Value::Object(xmap);

    let token = Token::new(header, claims).sign_with_key(&kk).unwrap();
    println!("token is {}", token.as_str());
    token.as_str().to_string()
}
