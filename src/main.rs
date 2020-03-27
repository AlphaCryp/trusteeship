use bls;
fn main() {
    let (private_key, public_key, g) = bls::key_gen();
    let msg = vec![1; 20];
    let sig_r = bls::sign(msg.clone(), private_key.clone());
    let r_r = bls::verify(msg.clone(), sig_r.clone(), public_key.clone(), g.clone());

    let self_id = 1usize.to_be_bytes();
    let other_id = 2usize.to_be_bytes();

    let msg1 = bls::blind(msg.clone(), self_id.to_vec(), other_id.to_vec());
    let msg2 = bls::blind(msg.clone(), other_id.to_vec(), self_id.to_vec());

    let (p1, k1) = bls::derived(g.clone(), self_id.to_vec(), private_key.clone());
    let (p2, k2) = bls::derived(g.clone(), self_id.to_vec(), private_key.clone());

    let sig1 = bls::sign(msg1, p1.clone());
    let sig2 = bls::sign(msg2, p2.clone());

    let sig = bls::aggregate(sig1.clone(), sig2.clone());
    let r = bls::verify(msg.clone(), sig.clone(), public_key.clone(), g.clone());

    println!("{:?}\n{:?}", sig_r, sig);
    println!("{}", r_r)
}
