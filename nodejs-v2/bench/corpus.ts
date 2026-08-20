/**
 * Labeled PII benchmark corpus — HR-flavored documents with ground-truth PII.
 *
 * Each entity is the exact substring that MUST be redacted. The benchmark
 * locates it in the text and checks whether the detector covered that span.
 * Recall is the metric that matters for a shield: an unrecalled entity is a
 * real leak to the LLM.
 *
 * Keep this synthetic (no real people). Extend with de-identified samples from
 * our own HR/contract docs to make the benchmark representative.
 */
export interface LabeledEntity {
  text: string;
  type:
    | "PERSON"
    | "EMAIL"
    | "PHONE"
    | "US_SSN"
    | "CREDIT_CARD"
    | "ADDRESS"
    | "DOB"
    | "MONEY"
    | "ORG"
    | "ID";
}

export interface LabeledDoc {
  id: string;
  text: string;
  entities: LabeledEntity[];
}

export const CORPUS: LabeledDoc[] = [
  {
    id: "offer-letter",
    text: `Dear Marcus Whitfield,

We are pleased to offer you the position of Senior Analyst at Northwind Robotics.
Your annual salary will be $142,500, paid biweekly. Please confirm using the email
we have on file, marcus.whitfield@gmail.com, or call 415-555-0198.

Your start date is March 3, 2027. For payroll, we have your SSN as 512-84-2213 and
your mailing address as 88 Larkspur Lane, Oakland, CA 94612.`,
    entities: [
      { text: "Marcus Whitfield", type: "PERSON" },
      { text: "Northwind Robotics", type: "ORG" },
      { text: "$142,500", type: "MONEY" },
      { text: "marcus.whitfield@gmail.com", type: "EMAIL" },
      { text: "415-555-0198", type: "PHONE" },
      { text: "512-84-2213", type: "US_SSN" },
      { text: "88 Larkspur Lane, Oakland, CA 94612", type: "ADDRESS" },
    ],
  },
  {
    id: "intake-form",
    text: `EMPLOYEE INTAKE

Full name: Priya Ramaswamy
Date of birth: 07/14/1991
Personal email: priya.r91@outlook.com
Mobile: (312) 555-7742
Emergency contact: Devon Clarke, 312-555-9981
Bank routing: 021000021, account 483920117
Home: 4102 W Belmont Ave, Apt 6, Chicago, IL 60641`,
    entities: [
      { text: "Priya Ramaswamy", type: "PERSON" },
      { text: "07/14/1991", type: "DOB" },
      { text: "priya.r91@outlook.com", type: "EMAIL" },
      { text: "(312) 555-7742", type: "PHONE" },
      { text: "Devon Clarke", type: "PERSON" },
      { text: "312-555-9981", type: "PHONE" },
      { text: "483920117", type: "ID" },
      { text: "4102 W Belmont Ave, Apt 6, Chicago, IL 60641", type: "ADDRESS" },
    ],
  },
  {
    id: "perf-review",
    text: `Performance Review — Q4

Reviewer: Alicia Fontaine
Employee: Sam Okafor (employee ID 44831)
Sam consistently exceeded targets this quarter. One concern raised by Tomás Herrera
in accounting regarding the reimbursement filed under card 4539 8712 3390 1174.
Recommended raise brings base to $98,000.`,
    entities: [
      { text: "Alicia Fontaine", type: "PERSON" },
      { text: "Sam Okafor", type: "PERSON" },
      { text: "44831", type: "ID" },
      { text: "Tomás Herrera", type: "PERSON" },
      { text: "4539 8712 3390 1174", type: "CREDIT_CARD" },
      { text: "$98,000", type: "MONEY" },
    ],
  },
  {
    id: "termination",
    text: `CONFIDENTIAL — Separation Notice

This confirms the separation of employment for Rebecca Nwosu, effective April 30.
Final pay of $6,214.55 will be deposited. COBRA paperwork mailed to
rnwosu.home@proton.me. Questions to HR lead Grigory Palahniuk at 646-555-0114.`,
    entities: [
      { text: "Rebecca Nwosu", type: "PERSON" },
      { text: "$6,214.55", type: "MONEY" },
      { text: "rnwosu.home@proton.me", type: "EMAIL" },
      { text: "Grigory Palahniuk", type: "PERSON" },
      { text: "646-555-0114", type: "PHONE" },
    ],
  },
  {
    id: "benefits",
    text: `Benefits Enrollment — Dependent Info

Primary: Yuki Tanaka, SSN 388-11-9042
Spouse: Oluwaseun Adeyemi
Child 1: Mei Tanaka, DOB 2015-09-02
Contact: 27 Seaside Blvd, Santa Cruz, CA 95060; ytanaka@company.com`,
    entities: [
      { text: "Yuki Tanaka", type: "PERSON" },
      { text: "388-11-9042", type: "US_SSN" },
      { text: "Oluwaseun Adeyemi", type: "PERSON" },
      { text: "Mei Tanaka", type: "PERSON" },
      { text: "2015-09-02", type: "DOB" },
      { text: "27 Seaside Blvd, Santa Cruz, CA 95060", type: "ADDRESS" },
      { text: "ytanaka@company.com", type: "EMAIL" },
    ],
  },
];
