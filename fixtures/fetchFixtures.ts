import * as messages from "./fixture_data/messages.json";
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
    readonly signature?: mockRngInputs;
    readonly proof?: mockRngInputs;
}


export interface CommitmentFixture {
    readonly caseName: string;
    readonly mockRngParameters: mockRngParameters;
    readonly committedMessages: string[];
    readonly proverBlind: string;
    readonly commitmentWithProof: string;
    readonly result: { valid: false; reason: string } | { valid: true };
}

interface signatureTrace {
  readonly B: string;
  readonly domain: string;
}

export interface SignatureFixtureData {
  readonly caseName: string;
  readonly signature: string;
  readonly header: string;
  readonly messages: string[];
  readonly committedMessages?: string[];
  result: { valid: false; reason: string } | { valid: true };
  readonly signerKeyPair: {
    readonly publicKey: string;
    readonly secretKey: string;
  };
  trace: signatureTrace;
}

interface proofTrace {
  readonly A_bar: string;
  readonly B_bar: string;
  readonly T: string;
  readonly domain: string;
  readonly challenge: string;
}

export interface ProofFixtureData {
  readonly caseName: string;
  readonly signerPublicKey: string;
  readonly header: string;
  readonly signature: string;
  readonly presentationHeader: string;
  readonly revealedMessages: { [index: string]: string };
  readonly totalMessageCount: number;
  readonly proof: string;
  readonly trace: proofTrace;
  result: { valid: false; reason: string } | { valid: true };
}

export interface GeneratorFixtureData {
  readonly P1: string;
  readonly Q1: string;
  readonly Q2: string;
  readonly MsgGenerators: string[];
}

export interface H2sFixtureData {
  readonly caseName: string;
  readonly message: string;
  readonly dst: string;
  readonly count: number;
  readonly scalars: string[];
}

export interface MapMessageToScalarCase {
  message: string;
  scalar: string;
}

export interface MapMessageToScalarFixtureData {
  readonly caseName: string;
  readonly dst: string;
  readonly cases: ReadonlyArray<MapMessageToScalarCase>
}

export interface MockRngFixtureData {
  readonly caseName: string,
  readonly seed: string,
  readonly dst: string,
  readonly count: number,
  readonly mockedScalars: string[];
}

export interface KeyPairFixtureData {
  readonly caseName: string,
  readonly keyMaterial: string,
  readonly keyInfo: string,
  readonly keyPair: {
    readonly secretKey: string,
    readonly publicKey: string
  }
}

export interface Fixture<T> {
  readonly name: string
  readonly value: T
}

const fetchNestedFixtures = <T>(name: string, input: any): ReadonlyArray<Fixture<T>> => {
  if (input.caseName || input.MsgGenerators || input.mockedScalars) {
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

export const generatorFixtures = fetchPerSuiteFixtures<CommitmentFixture>("", /generators.json/);
export const commitmentFixtures = fetchPerSuiteFixtures<CommitmentFixture>("/nymCommit");
export const signatureFixtures = fetchPerSuiteFixtures<SignatureFixtureData>("/nymSignature");
export const proofFixtures = fetchPerSuiteFixtures<ProofFixtureData>("/nymProof");

console.log(proofFixtures)

export { messages };
