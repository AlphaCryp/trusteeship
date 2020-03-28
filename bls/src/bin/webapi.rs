use async_std::io;
use async_std::task;
use bls;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, sync::RwLock};

#[derive(Deserialize, Serialize, Debug)]
struct Derive {
    g: String,
    ids: Vec<usize>,
}

#[derive(Deserialize, Serialize, Debug)]
struct Msg {
    msg: String,
    ids: Vec<usize>,
}

#[derive(Deserialize, Serialize, Debug)]
struct VerifyMsg {
    sig: String,
    msg: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct Signature {
    sig: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct Pair {
    sk: String,
    pk: String,
    g: String,
}

struct State {
    state: RwLock<HashMap<(String, usize), Vec<u8>>>,
    key: (Vec<u8>, Vec<u8>, Vec<u8>),
}

async fn new(req: tide::Request<State>) -> tide::Response {
    let key = &req.state().key;

    let pair = Pair {
        sk: faster_hex::hex_string(&key.0).unwrap(),
        pk: faster_hex::hex_string(&key.1).unwrap(),
        g: faster_hex::hex_string(&key.2).unwrap(),
    };

    tide::Response::new(200).body_json(&pair).unwrap()
}

async fn derive(mut req: tide::Request<State>) -> tide::Response {
    let derive: Derive = {
        let res = req.body_json().await;

        if let Err(e) = res {
            return tide::Response::new(400)
                .body_json(&json!({"res": e.to_string()}))
                .unwrap();
        }

        res.unwrap()
    };

    let mut g = vec![0; derive.g.len() >> 1];
    let res = faster_hex::hex_decode(derive.g.as_ref(), &mut g);

    if let Err(e) = res {
        return tide::Response::new(400)
            .body_json(&json!({"res": e.to_string()}))
            .unwrap();
    }

    let rand = bls::rand();

    let self_id = 1usize;
    let other_id = 2usize;

    let gl = req.state();
    let key = &gl.key;
    let mut state = gl.state.write().unwrap();

    let (p1, _k1) = bls::derived(
        g.clone(),
        rand.clone(),
        self_id.to_be_bytes().to_vec(),
        key.0.clone(),
    );

    let (p2, _k2) = bls::derived(
        g.clone(),
        rand.clone(),
        other_id.to_be_bytes().to_vec(),
        key.0.clone(),
    );
    state.insert((derive.g.clone(), self_id), p1);
    state.insert((derive.g.clone(), other_id), p2);

    tide::Response::new(200)
        .body_json(&json!({"res": true}))
        .unwrap()
}

async fn sign(mut req: tide::Request<State>) -> tide::Response {
    let msg_r: Msg = {
        let res = req.body_json().await;
        if let Err(e) = res {
            return tide::Response::new(400)
                .body_json(&json!({"res": e.to_string()}))
                .unwrap();
        }
        res.unwrap()
    };

    let mut msg = vec![0; msg_r.msg.len() >> 1];
    let res = faster_hex::hex_decode(msg_r.msg.as_ref(), &mut msg);

    if let Err(e) = res {
        return tide::Response::new(400)
            .body_json(&json!({"res": e.to_string()}))
            .unwrap();
    }

    let state = req.state();
    let derived = state.state.read().unwrap();

    let mut sig1 = Vec::new();
    let mut sig2 = Vec::new();

    for ((g, id), p) in derived.iter() {
        if id == &1usize {
            let (msg1, _) = bls::blind(
                msg.clone(),
                p.clone(),
                id.to_be_bytes().to_vec(),
                2usize.to_be_bytes().to_vec(),
            );
            sig1 = bls::sign_group(msg1.clone(), p.clone());
        }
        if id == &2usize {
            let (msg2, _) = bls::blind(
                msg.clone(),
                p.clone(),
                id.to_be_bytes().to_vec(),
                1usize.to_be_bytes().to_vec(),
            );
            sig2 = bls::sign_group(msg2.clone(), p.clone());
        }
    }

    let sig = bls::aggregate(sig1.clone(), sig2.clone());

    let sig = Signature {
        sig: faster_hex::hex_string(&sig).unwrap(),
    };

    tide::Response::new(200).body_json(&sig).unwrap()
}

async fn verify(mut req: tide::Request<State>) -> tide::Response {
    let msg_r: VerifyMsg = {
        let res = req.body_json().await;
        if let Err(e) = res {
            return tide::Response::new(400)
                .body_json(&json!({"res": e.to_string()}))
                .unwrap();
        }
        res.unwrap()
    };

    let mut sig = vec![0; msg_r.sig.len() >> 1];
    let res = faster_hex::hex_decode(msg_r.sig.as_ref(), &mut sig);

    if let Err(e) = res {
        return tide::Response::new(400)
            .body_json(&json!({"res": e.to_string()}))
            .unwrap();
    }

    let mut msg = vec![0; msg_r.msg.len() >> 1];
    faster_hex::hex_decode(msg_r.msg.as_ref(), &mut msg).unwrap();

    let state = req.state();

    let r = bls::verify(
        msg.clone(),
        sig.clone(),
        state.key.1.clone(),
        state.key.2.clone(),
    );

    tide::Response::new(200)
        .body_json(&json!({ "res": r }))
        .unwrap()
}

fn main() -> io::Result<()> {
    task::block_on(async {
        let (private_key, public_key, g) = bls::key_gen();

        let state = State {
            state: RwLock::new(HashMap::default()),
            key: (private_key, public_key, g),
        };
        let mut app = tide::with_state(state);

        app.at("/derive").post(derive);
        app.at("/new").get(new);
        app.at("/sign").post(sign);
        app.at("/verify").post(verify);

        app.listen("0.0.0.0:8080").await?;
        Ok(())
    })
}
