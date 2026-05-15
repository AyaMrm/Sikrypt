use crate::algorithms::{
    asymmetric::rsa::{self, RsaKeyPair},
    signature::rsa_pss::{self, RsaPssSignature},
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ballot {
    pub voter_id: String,
    pub candidate: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBallot {
    pub ballot: Ballot,
    pub signature: RsaPssSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VotingError {
    InvalidSignature,
    DuplicateVote,
}

fn canonical_ballot(ballot: &Ballot) -> String {
    format!("{}::{}", ballot.voter_id, ballot.candidate)
}

pub fn sign_ballot(ballot: Ballot, key_pair: &RsaKeyPair) -> SignedBallot {
    let signature = rsa_pss::sign(&canonical_ballot(&ballot), key_pair)
        .expect("RSA signing should succeed for a valid educational key pair");

    SignedBallot { ballot, signature }
}

pub fn verify_ballot(signed_ballot: &SignedBallot, key_pair: &RsaKeyPair) -> bool {
    rsa_pss::verify(
        &canonical_ballot(&signed_ballot.ballot),
        &signed_ballot.signature,
        key_pair,
    )
    .unwrap_or(false)
}

pub fn tally_votes(
    signed_ballots: &[SignedBallot],
    key_pair: &RsaKeyPair,
) -> Result<HashMap<String, u32>, VotingError> {
    let mut seen_voters = HashSet::new();
    let mut tally = HashMap::new();

    for signed_ballot in signed_ballots {
        if !verify_ballot(signed_ballot, key_pair) {
            return Err(VotingError::InvalidSignature);
        }

        if !seen_voters.insert(signed_ballot.ballot.voter_id.clone()) {
            return Err(VotingError::DuplicateVote);
        }

        *tally
            .entry(signed_ballot.ballot.candidate.clone())
            .or_insert(0) += 1;
    }

    Ok(tally)
}

pub fn demo_voter_key_pair() -> Result<RsaKeyPair, rsa::RsaError> {
    rsa::generate_key_pair(61, 53, 17)
}

#[cfg(test)]
mod tests {
    use super::{demo_voter_key_pair, sign_ballot, tally_votes, Ballot, VotingError};

    #[test]
    fn tallies_verified_votes() {
        let key_pair = demo_voter_key_pair().unwrap();
        let ballots = vec![
            sign_ballot(
                Ballot {
                    voter_id: "alice".to_string(),
                    candidate: "A".to_string(),
                },
                &key_pair,
            ),
            sign_ballot(
                Ballot {
                    voter_id: "bob".to_string(),
                    candidate: "B".to_string(),
                },
                &key_pair,
            ),
            sign_ballot(
                Ballot {
                    voter_id: "charlie".to_string(),
                    candidate: "A".to_string(),
                },
                &key_pair,
            ),
        ];

        let tally = tally_votes(&ballots, &key_pair).unwrap();
        assert_eq!(tally.get("A"), Some(&2));
        assert_eq!(tally.get("B"), Some(&1));
    }

    #[test]
    fn rejects_duplicate_vote() {
        let key_pair = demo_voter_key_pair().unwrap();
        let ballots = vec![
            sign_ballot(
                Ballot {
                    voter_id: "alice".to_string(),
                    candidate: "A".to_string(),
                },
                &key_pair,
            ),
            sign_ballot(
                Ballot {
                    voter_id: "alice".to_string(),
                    candidate: "B".to_string(),
                },
                &key_pair,
            ),
        ];

        let result = tally_votes(&ballots, &key_pair);
        assert_eq!(result, Err(VotingError::DuplicateVote));
    }
}
