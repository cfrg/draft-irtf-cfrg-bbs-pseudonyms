import { promises } from "fs";
import * as path from "path";
import * as fixtures from "./fetchFixtures";
import get from "lodash.get";

// matching lines of the form "name = {{ $<fixture_path> }}" (for
// example "m_1 = {{ $messages[1] }}" etc).
// The opening bracket may be `{{` or `{{ #`, and is captured by group 4.
// `{{ # $<fixture_path> }}` is used for section headings (e.g., caseName),
// which are inserted without quotes and without line wrapping.
const VARIABLE_REGEX = /(([^\S\n\t]*[a-zA-Z0-9_~]+\d*)\s=\s)?(({{|{{ #) \$)([a-zA-Z_|.|\-|\d|\[|\]]*)( }},?)$/gm

const DRAFT_NAME = "../draft-irtf-cfrg-bbs-per-verifier-linkability.md";

// Maximum line length for populated values in the draft.
const MAX_LINE = 72;

function formatValue(el: string | any[], skipQuotes: boolean): string {
  if (Array.isArray(el)) {
    return "[ " + el.map(elel => formatValue(elel, skipQuotes)).join(", ") + " ]";
  } else if (skipQuotes) {
    return el;
  } else {
    return "\x22" + el + "\x22";
  }
}

// Wrap a value that follows "name = " (of length intent_len) so that no line
// is longer than MAX_LINE. Continuation lines are indented to one past the
// "= ", i.e., aligned after the opening quote or bracket.
function wrapValue(value: string, intent_len: number): string {
  const first_len = MAX_LINE - intent_len;
  const rest_len = MAX_LINE - intent_len - 1;
  if (rest_len <= 0) {
    throw Error("Not enough space in the line to add the fixture");
  }
  const lines = [value.slice(0, first_len)];
  for (let i = first_len; i < value.length; i += rest_len) {
    lines.push(" ".repeat(intent_len + 1) + value.slice(i, i + rest_len));
  }
  return lines.join("\n");
}

const main = async () => {
  // Read the text of the draft out
  const filePath = path.join(process.env.PWD as string, DRAFT_NAME);
  // By default the draft is populated in place, which replaces the templates.
  // Pass an output path to write the populated draft there instead, e.g.,
  // npm run populate-fixtures -- ../temp/output.md
  const outPath = process.argv[2]
    ? path.resolve(process.env.PWD as string, process.argv[2])
    : filePath;
  let fileContents = (await promises.readFile(filePath)).toString();

  const results = Array.from(fileContents.matchAll(VARIABLE_REGEX)).map(
    (item: any) => {
      const [_fullmatch, indent, _varname, _substitee, openBracket, path] = item;
      return {
        match: openBracket + " $" + path + " }}",
        path,
        intent: indent,
        isHeading: openBracket === '{{ #',
      };
    }
  );

  const missing: string[] = [];
  results.forEach((result) => {
    const fixtureValue = get(fixtures, result.path);
    if (fixtureValue === undefined) {
      missing.push(result.path);
      return;
    }
    var value = formatValue(fixtureValue, result.isHeading);

    if (!result.isHeading) {
      const intent_len = result.intent ? result.intent.length : 0;
      value = wrapValue(value, intent_len);
    }

    // remove trailing whitespace from the value to be added in the draft
    value = value.split("\n").map(line => line.trimEnd()).join("\n").trim();

    fileContents = fileContents.replace(result.match, value);
  });

  if (missing.length > 0) {
    throw Error("No fixture value for: " + missing.join(", "));
  }

  // Write an updated copy of the file
  await promises.mkdir(path.dirname(outPath), { recursive: true });
  await promises.writeFile(outPath, fileContents);
};

main();
