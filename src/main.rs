use bls;
fn main() {
    let (private_key, public_key, g) = bls::key_gen();
    let msg = vec![3; 20];
    let sig_r = bls::sign(msg.clone(), private_key.clone());
    let r_r = bls::verify(msg.clone(), sig_r.clone(), public_key.clone(), g.clone());

    let self_id = 1usize.to_be_bytes();
    let other_id = 2usize.to_be_bytes();

    let rand = bls::rand();

    let (p1, k1) = bls::derived(g.clone(), rand.clone(), self_id.to_vec(), private_key.clone());
    let (p2, k2) = bls::derived(g.clone(), rand.clone(), other_id.to_vec(), private_key.clone());


    let (msg1, tmp1) = bls::blind(msg.clone(), p1.clone(), self_id.to_vec(), other_id.to_vec());
    let (msg2, tmp2) = bls::blind(msg.clone(), p2.clone(), other_id.to_vec(), self_id.to_vec());


    let x = bls::restore(tmp1.clone(), tmp2.clone());
    let sig1 = bls::sign_group(msg1.clone(), p1.clone());
    let sig2 = bls::sign_group(msg2.clone(), p2.clone());

    let sig = bls::aggregate(sig1.clone(), sig2.clone());


    let r = bls::verify(msg.clone(), sig.clone(), public_key.clone(), g.clone());



    let r_1 = bls::verify(msg1.clone(), sig1.clone(), k1.clone(), g.clone());
    let r_2 = bls::verify(msg2.clone(), sig2.clone(), k2.clone(), g.clone());

    // println!("{:?}\n{:?}", tmp1, tmp2);
    // println!("{:?}\n{:?}", x, private_key);
    // println!("{:?}\n{:?}", sig_r, sig);
    // println!("{}, {}", r_1, r_2);
    println!("{}", r);
    // println!("{}", r_r);

    println!("msg: \n{:?}\n{:?}", msg1, msg2)
}
