import * as path from "path";
import { readdirSync  } from 'fs';

const FIXTURES_FILE = "./fixture_data"

const isObject = (value: unknown) => value && typeof value === "object";

// tslint:disable-next-line:no-var-requires
const resolveFixtures = (subDirectory: string, filter: any) =>
  require("require-all")({
    dirname: `${__dirname}/${subDirectory}`,
    filter: filter,
    excludeDirs: [".github", "tests"],
    map: (__: unknown, path: unknown) => {
      return `${path}`;
    },
  });

const suites = readdirSync(FIXTURES_FILE, { withFileTypes: true })
                .filter(dirent => dirent.isDirectory())
                .map(dirent => dirent.name);


interface mockRngInputs {
    readonly DST: string;
    readonly count: number;
}

interface mockRngParameters {
    readonly SEED: string;
    readonly commit?: mockRngInputs;
    readonly proof?: mockRngInputs;
}

// A message is a [flag, value] pair. The flag is "HASH" or "RAW" and the
// value is hex encoded.
type FlaggedMessage = [string, string];

// Each disclosure is "DISCLOSE", "HIDE" or "COMMIT".
type Disclosure = string;

type Result = { valid: false; reason: string } | { valid: true };

interface commitmentTrace {
  readonly random_scalars: {
    readonly s_tilde: string;
    readonly m_tildes: string[];
  };
}

export interface CommitmentFixture {
  readonly caseName: string;
  readonly mockRngParameters: mockRngParameters;
  readonly blindMessages: FlaggedMessage[];
  readonly proverNyms: string[];
  readonly proverBlind: string;
  readonly commitmentWithProof: string;
  readonly result: Result;
  readonly trace: commitmentTrace;
}

interface signatureTrace {
  readonly B: string;
  readonly domain: string;
}

export interface SignatureFixtureData {
  readonly caseName: string;
  readonly mockRngParameters: mockRngParameters;
  readonly signerKeyPair: {
    readonly publicKey: string;
    readonly secretKey: string;
  };
  readonly header: string;
  readonly messages: FlaggedMessage[];
  readonly blindMessages: FlaggedMessage[];
  readonly proverNyms: string[];
  readonly signer_nym_entropy: string;
  readonly commitmentWithProof: string;
  readonly proverBlind: string;
  readonly nym_secrets: string[];
  readonly signature: string;
  readonly result: Result;
  readonly trace: signatureTrace;
}

interface proofTrace {
  readonly randomScalars: {
    readonly r1: string;
    readonly r2: string;
    readonly e_Tilde: string;
    readonly r1_Tilde: string;
    readonly r3_Tilde: string;
    readonly m_tilde_scalars: string[];
    readonly s_i: string[];
    readonly s_tilde_i: string[];
  };
  readonly A: string;
  readonly Abar: string;
  readonly Bbar: string;
  readonly D: string;
  readonly T1: string;
  readonly T2: string;
  readonly C_i: string[];
  readonly C_tilde_i: string[];
  readonly pseudonym: string;
  readonly Ut: string;
  readonly domain: string;
  readonly challenge: string;
}

export interface ProofFixtureData {
  readonly caseName: string;
  readonly mockRngParameters: mockRngParameters;
  readonly signerPublicKey: string;
  readonly signatureFile: string;
  readonly header: string;
  readonly presentationHeader: string;
  readonly context_id: string;
  readonly messageDisclosures: Disclosure[];
  readonly blindMessageDisclosures: Disclosure[];
  readonly L: number;
  readonly proof: string;
  readonly pseudonym: string;
  readonly result: Result;
  readonly add_zkp_info: {
    readonly committed_message_scalars: string[];
    readonly commitment_rands: string[];
  };
  readonly trace: proofTrace;
}

interface MsgGeneratorFixtureData {
  readonly api_id: string;
  readonly P1: string;
  readonly Q1: string;
  readonly MsgGenerators: string[];
}

export interface GeneratorFixtureData {
  readonly generators: MsgGeneratorFixtureData;
  readonly blindGenerators: MsgGeneratorFixtureData;
  readonly commitmentGenerators: {
    readonly api_id: string;
    readonly Y_0: string;
    readonly Y_1: string;
  };
}

export interface Fixture<T> {
  readonly name: string
  readonly value: T
}

// A fixture is a test case (has a caseName) or a set of generators (has
// MsgGenerators, or Y_0 for the committed disclosure generators).
const fetchNestedFixtures = <T>(name: string, input: any): ReadonlyArray<Fixture<T>> => {
  if (input.caseName || input.MsgGenerators || input.Y_0) {
    return [
      {
        name: path.basename(name).split(".")[0] as string,
        value: input,
      } as any,
    ];
  }
  if (!isObject(input)) {
    return [];
  }

  const extractedFixtures = Object.keys(input).map((key) =>
    fetchNestedFixtures(key, input[key])
  );
  return Array.prototype.concat.apply([], extractedFixtures);
};


const fetchPerSuiteFixtures = <T>(dir:string, filter = /.json$/) => {
  let fixtureMap = {}
  for (let suite of suites) {
    let suiteFixturesData = fetchNestedFixtures<T>(
      "", resolveFixtures(FIXTURES_FILE+"/"+suite+dir, filter)
      )
      .reduce((map, item: Fixture<T>) => {
        map = {
          ...map,
          [item.name]: item.value
        }
        return map
      }, {})

    fixtureMap = {
      ...fixtureMap,
      [suite]: suiteFixturesData
    }
  }

  return fixtureMap
}

export const generatorFixtures = fetchPerSuiteFixtures<GeneratorFixtureData>("", /generators.json/);
export const commitmentFixtures = fetchPerSuiteFixtures<CommitmentFixture>("/nymCommit");
export const signatureFixtures = fetchPerSuiteFixtures<SignatureFixtureData>("/nymSignature");
export const proofFixtures = fetchPerSuiteFixtures<ProofFixtureData>("/nymProof");
