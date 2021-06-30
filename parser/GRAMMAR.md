# Parser Grammar

This document describes the currently supported Datalog grammar.

## Term

Represents a Datalog type, can be one of: symbol, variable, integer, string, date, bytes, boolean, or set.

- symbol is prefixed with a `#` sign followed by text, e.g. `#read`
- variable is prefixed with a `$` sign followed by a string or an unsigned 32bit base-10 integer,  e.g. `$0` or `$variable1`
- integer is any base-10 int64
- string is any utf8 character sequence, between double quotes, e.g. `"/path/to/file.txt"`
- date is RFC3339 encoded, e.g. `2006-01-02T15:04:05Z07:00`
- bytes is an hexadecimal encoded string, prefixed with a `hex:` sequence
- boolean is either `true` or `false`
- set is a sequence of any of the above types, except variable, between brackets, e.g. `[#read, #write, #update, "file1", "file2"]`

## Predicate

A predicate is a list of terms, grouped under a name in the form `Name(Term0, Term1, ..., TermN)` , e.g. `parent(#a, #b)`.

## Constraints

Constraints allows performing checks on a variable, below is the list of available operations by type and their expected format.

### Integer

- Equal: `$i == 1`
- Greater than: `$i > 1`
- Greater than or equal: `$i >= 1`
- Less than: `$i < 1`
- Less than or equal: `$i <= 1`
- In: `$i in [1, 2, 3]`
- Not in: `$i not in [1, 2, 3]`

###  String

- Equal: `$s == "abc"`
- Starts with: `prefix($s, "abc")`
- Ends with: `suffix($s, "abc")`
- Regular expression: `match($s, "^abc\s+def$") `
- In: `$s in ["abc", "def"]`
- Not in: `$s not in ["abc", "def"]`

### Date

- Before: `$date <= "2006-01-02T15:04:05Z07:00"`
- After: `$date >= "2006-01-02T15:04:05Z07:00"`

### Symbols

- In:`$sym in [#a, #b, #c]`
- Not in:`$sym not in [#a, #b, #c]`

### Bytes

- Equal: `$b == "hex:3df97fb5"`
- In: `$b in ["hex:3df97fb5", "hex:4a8feed1"]`
- Not in: `$b not in ["hex:3df97fb5", "hex:4a8feed1"]`

### Set

- Any: `$set in [#read, #write]`
- None: `$set not in [#read, #write]`

## Fact

A fact is a single predicate that does not contain any variables, e.g. `right(#authority, "file1.txt", #read)`.

# Rule

A rule is formed from a head, a body, and a list of constraints.
The head is a single predicate, the body is a list of predicates, and followed by an optional list of constraints.

It has the format: `Head <- Body @ Constraints`.

e.g. `right(#authority, $file, #read) <- resource(#ambient, $file), owner(#ambient, $user, $file) @ $user == "username", prefix($file, "/home/username")`

# Check

A check is a list of rules with the format: `[ rule0 || rule1 || ... || ruleN ]`
