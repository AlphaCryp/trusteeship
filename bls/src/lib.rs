#[link(name = "pbc")]
#[link(name = "gmp")]
extern "C" {
    pub fn sign_c(out: *mut u8, out_len: *mut usize, msg: *mut u8, msg_len: usize, data: *mut u8);
    pub fn verify_c(
        msg: *mut u8,
        msg_len: usize,
        data_s: *mut u8,
        data_g: *mut u8,
        data_p: *mut u8,
    ) -> i32;
    pub fn key_gen_c(
        out_sk: *mut u8,
        sk_len: *mut usize,
        out_pk: *mut u8,
        pk_len: *mut usize,
        out_g: *mut u8,
        g_len: *mut usize,
    );
    pub fn aggregate_c(sig1: *mut u8, sig1: *mut u8, out: *mut u8, out_len: *mut usize);
    pub fn derived_c(
        g: *mut u8,
        rand: *mut u8,
        id: *mut u8,
        sk: *mut u8,
        out_sk: *mut u8,
        sk_len: *mut usize,
        out_pk: *mut u8,
        pk_len: *mut usize,
    );
    pub fn blind_c(
        msg: *mut u8,
        msg_len: usize,
        self_id: *mut u8,
        other_id: *mut u8,
        msg_out: *mut u8,
        out_len: *mut usize,
        tmp_out: *mut u8,
        tmp_len: *mut usize,
        sk: *mut u8,
    );

    pub fn restore_c(s1: *mut u8, s2: *mut u8, s3: *mut u8, out_len: *mut usize);

    pub fn rand_c(rand_out: *mut u8, out_len: *mut usize);

    pub fn sign_group_c(out: *mut u8, out_len: *mut usize, msg: *mut u8, data: *mut u8);
}

//sign the msg, only msg[0..20] is used.
pub fn sign(mut msg: Vec<u8>, mut private_key: Vec<u8>) -> Vec<u8> {
    unsafe {
        let mut sig = Vec::with_capacity(30);
        let mut sig_len = 0usize;
        let msg_len = msg.len();

        sign_c(
            sig.as_mut_ptr(),
            &mut sig_len,
            msg.as_mut_ptr(),
            msg_len,
            private_key.as_mut_ptr(),
        );

        sig.set_len(sig_len);
        sig
    }
}

pub fn verify(mut msg: Vec<u8>, mut sig: Vec<u8>, mut public_key: Vec<u8>, mut g: Vec<u8>) -> bool {
    unsafe {
        let msg_len = msg.len();

        let r = verify_c(
            msg.as_mut_ptr(),
            msg_len,
            sig.as_mut_ptr(),
            g.as_mut_ptr(),
            public_key.as_mut_ptr(),
        );

        r != 0
    }
}

pub fn key_gen() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    unsafe {
        let mut private_key = Vec::with_capacity(1024);
        let mut private_len = 0usize;
        let mut public_key = Vec::with_capacity(1024);
        let mut public_len = 0usize;
        let mut g = Vec::with_capacity(1024);
        let mut g_len = 0usize;

        key_gen_c(
            private_key.as_mut_ptr(),
            &mut private_len,
            public_key.as_mut_ptr(),
            &mut public_len,
            g.as_mut_ptr(),
            &mut g_len,
        );

        private_key.set_len(private_len);
        private_key.shrink_to_fit();

        public_key.set_len(public_len);
        public_key.shrink_to_fit();

        g.set_len(g_len);
        g.shrink_to_fit();
        (private_key, public_key, g)
    }
}

pub fn aggregate(mut sig1: Vec<u8>, mut sig2: Vec<u8>) -> Vec<u8> {
    let mut aggregate_sig = Vec::with_capacity(1024);
    let mut aggregate_sig_len = 0usize;

    unsafe {
        aggregate_c(
            sig1.as_mut_ptr(),
            sig2.as_mut_ptr(),
            aggregate_sig.as_mut_ptr(),
            &mut aggregate_sig_len,
        );

        aggregate_sig.set_len(aggregate_sig_len);
    }

    aggregate_sig
}

pub fn derived(
    mut g: Vec<u8>,
    mut rand: Vec<u8>,
    mut id: Vec<u8>,
    mut sk: Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let mut out_sk = Vec::with_capacity(1024);
    let mut sk_len = 0usize;
    let mut out_pk = Vec::with_capacity(1024);
    let mut pk_len = 0usize;

    unsafe {
        derived_c(
            g.as_mut_ptr(),
            rand.as_mut_ptr(),
            id.as_mut_ptr(),
            sk.as_mut_ptr(),
            out_sk.as_mut_ptr(),
            &mut sk_len,
            out_pk.as_mut_ptr(),
            &mut pk_len,
        );
        out_sk.set_len(sk_len);
        out_pk.set_len(pk_len);
    }

    (out_sk, out_pk)
}

pub fn blind(
    mut msg: Vec<u8>,
    mut sk: Vec<u8>,
    mut self_id: Vec<u8>,
    mut other_id: Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let mut msg_out = Vec::with_capacity(1024);
    let msg_len = msg.len();
    let mut out_len = 0usize;
    let mut tmp_out = Vec::with_capacity(1024);
    let mut tmp_len = 0usize;

    unsafe {
        blind_c(
            msg.as_mut_ptr(),
            msg_len,
            self_id.as_mut_ptr(),
            other_id.as_mut_ptr(),
            msg_out.as_mut_ptr(),
            &mut out_len,
            tmp_out.as_mut_ptr(),
            &mut tmp_len,
            sk.as_mut_ptr(),
        );

        tmp_out.set_len(tmp_len);
        msg_out.set_len(out_len);
    }

    (msg_out, tmp_out)
}

pub fn restore(mut s1: Vec<u8>, mut s2: Vec<u8>) -> Vec<u8> {
    let mut tmp_out = Vec::with_capacity(1024);
    let mut tmp_len = 0usize;

    unsafe {
        restore_c(
            s1.as_mut_ptr(),
            s2.as_mut_ptr(),
            tmp_out.as_mut_ptr(),
            &mut tmp_len,
        );
        tmp_out.set_len(tmp_len);
    }

    tmp_out
}

pub fn rand() -> Vec<u8> {
    let mut tmp_out = Vec::with_capacity(1024);
    let mut tmp_len = 0usize;

    unsafe {
        rand_c(tmp_out.as_mut_ptr(), &mut tmp_len);
        tmp_out.set_len(tmp_len);
    }

    tmp_out
}

pub fn sign_group(mut msg: Vec<u8>, mut private_key: Vec<u8>) -> Vec<u8> {
    unsafe {
        let mut sig = Vec::with_capacity(30);
        let mut sig_len = 0usize;

        sign_group_c(
            sig.as_mut_ptr(),
            &mut sig_len,
            msg.as_mut_ptr(),
            private_key.as_mut_ptr(),
        );

        sig.set_len(sig_len);
        sig
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (private_key, public_key, g) = key_gen();
        let msg = vec![1; 20];
        let sig = sign(msg.clone(), private_key.clone());
        let r = verify(msg, sig.clone(), public_key.clone(), g.clone());
        assert_eq!(r, true);

        let msg = vec![2; 20];
        let r = verify(msg, sig.clone(), public_key.clone(), g.clone());
        assert_eq!(r, false);
    }
}
