"""Deterministic, clearly-marked synthetic BEC / impersonation / fraud emails.

Every sample:
- uses only fictional people and reserved domains (.test / .example, RFC 2606/6761);
- carries `X-AIPISH-Synthetic: true` and a Message-ID under synthetic.aipish.test;
- has source="synthetic" and a template id, so it is always distinguishable
  from real data and all samples of one template land in the same split.
Dates are artificial (spread over 2000-2007 to overlap the real corpora's era,
so date cannot act as a "synthetic" shortcut); they carry no meaning.
"""
from __future__ import annotations

import datetime as dt
import random
from email.message import EmailMessage
from email.utils import format_datetime

from app.ml.dataset.normalize import RawMessage

DEFAULT_SEED = 20261118
DEFAULT_PER_TEMPLATE = 25

FIRST = ["Alex", "Priya", "Jordan", "Mei", "Tomas", "Aisha", "Daniel", "Sofia", "Ravi", "Elena",
         "Marcus", "Hana", "Lucas", "Nadia", "Owen", "Ines", "Kenji", "Grace", "Omar", "Lena"]
LAST = ["Hartley", "Varma", "Okafor", "Lindqvist", "Moreau", "Castillo", "Brennan", "Tanaka",
        "Novak", "Ferreira", "Quinn", "Albright", "Sato", "Kowalski", "Mendes", "Harlow"]
ORGS = [("Halvorsen Logistics", "halvorsen-logistics.test"),
        ("Brightwater Health", "brightwaterhealth.example"),
        ("Corvid Analytics", "corvid-analytics.test"),
        ("Larkspur Engineering", "larkspur-eng.example"),
        ("Meridian Foods", "meridianfoods.test"),
        ("Pinecrest Capital", "pinecrest-capital.example")]
VENDORS = [("Atlas Freight Supplies", "atlasfreight.test"),
           ("Kestrel Office Systems", "kestrel-office.example"),
           ("Silverline Packaging", "silverline-pack.test"),
           ("Orchard IT Services", "orchard-it.example")]
EXEC_TITLES = ["CEO", "CFO", "Managing Director", "VP Finance", "COO"]
STAFF_ROLES = ["Accounts Payable", "Finance", "Payroll", "HR", "Office Manager"]
AMOUNTS = ["4,850.00", "12,400.00", "27,930.00", "48,200.00", "9,775.50", "63,000.00", "18,640.00"]
CURRENCIES = ["USD", "EUR", "GBP"]
DEADLINES = ["before 3pm today", "by end of day", "within the hour", "first thing tomorrow",
             "before the bank cut-off"]
SIGNOFFS = ["Thanks", "Regards", "Best", "Sent from my mobile", "Thank you", "Cheers"]


def _lookalike(domain: str, rng: random.Random) -> str:
    name, tld = domain.rsplit(".", 1)
    variants = [
        name.replace("l", "1", 1) + "." + tld,
        name.replace("o", "0", 1) + "." + tld,
        name + "-mail." + tld,
        name + "." + ("example" if tld == "test" else "test"),
        name.replace("-", "", 1) + "-secure." + tld,
        name + "s." + tld,
    ]
    return rng.choice([v for v in variants if v != domain] or [name + "-co." + tld])


# Each template: family, sender style, subject variants, paragraph variants.
# Paragraph entries are alternatives; one is chosen per sample.
TEMPLATES: list[dict] = [
    # ── fraud: BEC wire transfer ────────────────────────────────────────
    {"id": "bec_wire_01", "family": "bec_wire_transfer", "sender": "exec_lookalike",
     "subjects": ["Urgent payment", "Wire needed today", "Quick favour - confidential", "Payment request"],
     "body": [["{staff_first}, are you at your desk?", "Hi {staff_first},", "{staff_first},"],
              ["I need you to process a wire of {currency} {amount} to a new supplier {deadline}.",
               "We have to settle an outstanding payment of {currency} {amount} {deadline}."],
              ["I am in meetings all day so email only, do not call.",
               "Keep this between us until the deal is announced."],
              ["I'll send the beneficiary details once you confirm."]]},
    {"id": "bec_wire_02", "family": "bec_wire_transfer", "sender": "exec_display_spoof",
     "subjects": ["Acquisition - strictly confidential", "Project {codename}", "Confidential transfer"],
     "body": [["Dear {staff_first},", "{staff_first} -"],
              ["We are closing the {codename} acquisition and our lawyers need a deposit of "
               "{currency} {amount} wired {deadline}."],
              ["Please treat this as strictly confidential and do not discuss it with anyone else in "
               "{org}.", "The board has approved it, you do not need further sign-off."],
              ["Reply and I will forward the escrow account details."]]},
    {"id": "bec_wire_03", "family": "bec_wire_transfer", "sender": "exec_freemail",
     "subjects": ["From my personal email", "Need this handled", "Re: transfer"],
     "body": [["Hi {staff_first}, writing from my personal account as I'm travelling."],
              ["Can you make a same-day transfer of {currency} {amount} to the account below {deadline}?"],
              ["Bank: Fictive Trust Bank\nAccount name: {vendor} Holdings\nIBAN: XX00 TEST 0000 {digits}"],
              ["Let me know once done and send me the confirmation."]]},
    # ── fraud: payroll redirect ─────────────────────────────────────────
    {"id": "payroll_01", "family": "bec_payroll_redirect", "sender": "employee_freemail",
     "subjects": ["Direct deposit change", "Change of bank details", "Update my payroll account"],
     "body": [["Hello {staff_role} team,", "Hi,"],
              ["I recently changed banks and would like my salary paid into my new account from the "
               "next pay run.", "Please update my direct deposit details before this month's payroll."],
              ["What information do you need from me? I can send the new account number today."],
              ["Thanks, {victim_name}"]]},
    {"id": "payroll_02", "family": "bec_payroll_redirect", "sender": "employee_lookalike",
     "subjects": ["Payroll update for {victim_first}", "New account for salary"],
     "body": [["Hi {staff_first},"],
              ["Please change my salary account to the one below, effective immediately.",
               "My old account has been closed, kindly use these details for my next payment."],
              ["Account: {digits}\nSort/Routing: 00-{digits_short}"],
              ["I'm out of the office so please confirm by email."]]},
    {"id": "payroll_03", "family": "bec_payroll_redirect", "sender": "employee_freemail",
     "subjects": ["Quick question about my pay", "Bank change before payday"],
     "body": [["Good morning,"],
              ["Is it too late to change where my pay goes this cycle? I have opened an account with "
               "an online bank."],
              ["I would appreciate it if this could be done {deadline}. I can't log in to the HR portal "
               "from my phone."],
              ["{signoff},\n{victim_name}"]]},
    # ── fraud: invoice with changed bank details ───────────────────────
    {"id": "invoice_01", "family": "invoice_bank_change", "sender": "vendor_lookalike",
     "subjects": ["Invoice {invoice} - updated remittance details", "Overdue invoice {invoice}"],
     "body": [["Dear {staff_role},"],
              ["Please find attached invoice {invoice} for {currency} {amount}.",
               "Our records show invoice {invoice} ({currency} {amount}) is now overdue."],
              ["Due to an audit our bank details have changed. Please make all future payments to the "
               "new account and disregard previous instructions."],
              ["Kind regards,\n{vendor_contact}\nAccounts Receivable, {vendor}"]]},
    {"id": "invoice_02", "family": "invoice_bank_change", "sender": "vendor_lookalike",
     "subjects": ["Change of banking information - {vendor}", "Important: new bank account"],
     "body": [["Hello,"],
              ["We are writing to inform all customers that {vendor} has moved its banking to a new "
               "provider."],
              ["Kindly update your vendor master file and settle the open balance of {currency} {amount} "
               "to the new account {deadline}.", "Payments to the old account will be returned."],
              ["Please confirm by return email once updated."]]},
    {"id": "invoice_03", "family": "invoice_bank_change", "sender": "vendor_freemail",
     "subjects": ["Re: payment status {invoice}", "Remittance query"],
     "body": [["Hi {staff_first},"],
              ["Following up on {invoice}. Our finance team noticed the payment has not arrived."],
              ["Please note we can only receive funds at our new account for now; the details are in "
               "the attached letter. Could you process {currency} {amount} {deadline}?"],
              ["{signoff},\n{vendor_contact}"]]},
    # ── fraud: gift cards ──────────────────────────────────────────────
    {"id": "giftcard_01", "family": "gift_card_request", "sender": "exec_display_spoof",
     "subjects": ["Small task", "Are you available?", "Quick request"],
     "body": [["{staff_first}, I need a favour."],
              ["I want to surprise some of the team with gift cards today. Can you buy {n} cards of "
               "{currency} 100 each?", "Please pick up {n} gift cards for a client appreciation event."],
              ["Scratch the back, take a photo of the codes and email them to me {deadline}."],
              ["I'll reimburse you. {signoff}"]]},
    {"id": "giftcard_02", "family": "gift_card_request", "sender": "exec_freemail",
     "subjects": ["Need your help", "Confidential"],
     "body": [["Hello {staff_first},"],
              ["I'm stuck in a conference and need {n} prepaid cards for a partner. It's urgent."],
              ["Buy them at any store, keep the receipts, and send me the card numbers and PINs here."],
              ["Don't mention it to anyone yet, it's a surprise."]]},
    {"id": "giftcard_03", "family": "gift_card_request", "sender": "exec_lookalike",
     "subjects": ["Staff reward", "Gift cards for the team"],
     "body": [["Hi,"],
              ["As a thank-you for the quarter I'd like to give the {staff_role} team gift cards."],
              ["Please get {n} cards ({currency} 50 each) {deadline} and email me the codes so I can "
               "send them personally."],
              ["{signoff},\n{exec_name}"]]},
    # ── fraud: advance fee ─────────────────────────────────────────────
    {"id": "advfee_01", "family": "advance_fee", "sender": "stranger_freemail",
     "subjects": ["Business proposal", "Confidential partnership", "Mutual benefit"],
     "body": [["Dear Friend,"],
              ["I am {stranger}, an auditor with a fictional overseas bank. I discovered a dormant account "
               "of {currency} {big_amount} whose owner died without heirs."],
              ["I seek a trusted partner to receive the funds. You will keep 30% for your assistance."],
              ["To begin, I need your full name, phone number and a small processing fee."]]},
    {"id": "advfee_02", "family": "advance_fee", "sender": "stranger_freemail",
     "subjects": ["You have won!", "Award notification", "Claim your prize"],
     "body": [["Congratulations!"],
              ["Your email address was selected in our international promotion and you have won "
               "{currency} {big_amount}."],
              ["To release your winnings, pay the clearance fee of {currency} {small_amount} and send "
               "your bank details to the claims agent."],
              ["Reply within 7 days or your prize will be forfeited."]]},
    {"id": "advfee_03", "family": "advance_fee", "sender": "stranger_freemail",
     "subjects": ["Inheritance claim", "Next of kin", "Estate of the late Mr {last}"],
     "body": [["Greetings,"],
              ["I am a barrister handling the estate of a late client who shares your surname, "
               "{last}. The estate is valued at {currency} {big_amount}."],
              ["As you could be presented as next of kin, we can share the proceeds equally."],
              ["Kindly send a copy of your ID and your direct telephone so we can proceed."]]},
    # ── impersonated: executive, non-financial ─────────────────────────
    {"id": "execimp_01", "family": "exec_impersonation", "sender": "exec_lookalike",
     "subjects": ["Are you available?", "Quick question", "Need you for something"],
     "body": [["{staff_first}, are you around?", "Hi {staff_first},"],
              ["I need you to handle something discreetly for me today.",
               "I'm tied up in a board meeting and need your help with a task."],
              ["Reply with your mobile number so I can text you the details."],
              ["{signoff}\n{exec_name}\n{exec_title}"]]},
    {"id": "execimp_02", "family": "exec_impersonation", "sender": "exec_display_spoof",
     "subjects": ["Employee records", "W-2 / tax forms request", "Staff list needed"],
     "body": [["Hi {staff_first},"],
              ["Please send me the full list of employees with their home addresses and tax forms for a "
               "review I am doing with the auditors.",
               "I need the current staff directory with personal contact details for a board request."],
              ["PDF is fine. I need it {deadline}."],
              ["{exec_name}"]]},
    {"id": "execimp_03", "family": "exec_impersonation", "sender": "exec_freemail",
     "subjects": ["New number", "Text me", "Using my personal email"],
     "body": [["Hello {staff_first},"],
              ["My work phone is being repaired. This is my personal email for the next few days."],
              ["Please don't reply to my work address. Send me the contact details of our main banking "
               "relationship manager, I need to speak to them."],
              ["{signoff},\n{exec_name}"]]},
    # ── impersonated: vendor / partner ─────────────────────────────────
    {"id": "vendimp_01", "family": "vendor_impersonation", "sender": "vendor_lookalike",
     "subjects": ["Updated contact list", "Account manager change", "Introduction"],
     "body": [["Dear {staff_first},"],
              ["I am the new account manager for {org} at {vendor}. {vendor_contact} has moved on."],
              ["Could you send me the names and emails of everyone in {staff_role} who approves our "
               "orders, so I can update our records?"],
              ["Best regards,\n{vendor_contact2}\n{vendor}"]]},
    {"id": "vendimp_02", "family": "vendor_impersonation", "sender": "vendor_lookalike",
     "subjects": ["Copy of signed contract", "Purchase order copies", "Documents needed"],
     "body": [["Hello,"],
              ["Our legal team is reviewing our agreement with {org} and we lost the signed copy."],
              ["Could you email the signed contract and the last three purchase orders {deadline}?"],
              ["Thank you,\n{vendor_contact}"]]},
    {"id": "vendimp_03", "family": "vendor_impersonation", "sender": "vendor_freemail",
     "subjects": ["Urgent - please call me", "Delivery problem"],
     "body": [["Hi {staff_first},"],
              ["There is a problem with your next delivery from {vendor}. I'm writing from my personal "
               "email as our system is down."],
              ["Please call me on +00 555 {digits_short} as soon as you can and keep this thread off the "
               "shared mailbox."],
              ["{vendor_contact}"]]},
    # ── impersonated: IT / HR ──────────────────────────────────────────
    {"id": "itimp_01", "family": "it_support_impersonation", "sender": "internal_lookalike",
     "subjects": ["Mailbox migration", "Action required: account review", "IT security check"],
     "body": [["Dear user,", "Hello {staff_first},"],
              ["We are migrating mailboxes this week. A member of the helpdesk will call you to verify "
               "your identity."],
              ["Please reply with your direct phone number and the best time to reach you."],
              ["{org} IT Service Desk"]]},
    {"id": "itimp_02", "family": "it_support_impersonation", "sender": "internal_lookalike",
     "subjects": ["HR: policy acknowledgement", "Updated handbook", "Benefits enrolment"],
     "body": [["Hi {staff_first},"],
              ["HR is updating employee records ahead of benefits enrolment."],
              ["Reply to this email with your date of birth, home address and employee number so we can "
               "confirm your file."],
              ["Human Resources, {org}"]]},
    {"id": "itimp_03", "family": "it_support_impersonation", "sender": "internal_lookalike",
     "subjects": ["Your laptop is due for replacement", "Device audit"],
     "body": [["Hello,"],
              ["Our records show your device is out of warranty. Please reply with the serial number and "
               "your manager's name so we can schedule a swap."],
              ["A technician will contact you by phone; do not raise a ticket for this."],
              ["{org} Desktop Support"]]},
]


def _sample(tpl: dict, idx: int, rng: random.Random) -> bytes:
    org, org_dom = rng.choice(ORGS)
    vendor, vendor_dom = rng.choice(VENDORS)
    exec_first, exec_last = rng.choice(FIRST), rng.choice(LAST)
    staff_first = rng.choice([f for f in FIRST if f != exec_first])
    victim_first, victim_last = rng.choice(FIRST), rng.choice(LAST)
    slots = {
        "org": org, "vendor": vendor, "staff_first": staff_first,
        "staff_role": rng.choice(STAFF_ROLES), "exec_name": f"{exec_first} {exec_last}",
        "exec_title": rng.choice(EXEC_TITLES), "victim_first": victim_first,
        "victim_name": f"{victim_first} {victim_last}", "amount": rng.choice(AMOUNTS),
        "currency": rng.choice(CURRENCIES), "deadline": rng.choice(DEADLINES),
        "signoff": rng.choice(SIGNOFFS), "codename": rng.choice(["Falcon", "Harbor", "Juniper", "Orion"]),
        "digits": f"{rng.randrange(10**7, 10**8)}", "digits_short": f"{rng.randrange(1000, 9999)}",
        "invoice": f"INV-{rng.randrange(10000, 99999)}", "n": str(rng.choice([3, 4, 5, 6, 8, 10])),
        "vendor_contact": f"{rng.choice(FIRST)} {rng.choice(LAST)}",
        "vendor_contact2": f"{rng.choice(FIRST)} {rng.choice(LAST)}",
        "stranger": f"{rng.choice(FIRST)} {rng.choice(LAST)}", "last": victim_last,
        "big_amount": f"{rng.randrange(2, 40)},{rng.randrange(100, 999)},000.00",
        "small_amount": f"{rng.randrange(150, 950)}.00",
    }
    style = tpl["sender"]
    if style == "exec_lookalike":
        name, addr = slots["exec_name"], f"{exec_first.lower()}.{exec_last.lower()}@{_lookalike(org_dom, rng)}"
    elif style == "exec_display_spoof":
        name, addr = slots["exec_name"], f"exec.office{rng.randrange(10, 99)}@mailhost.example"
    elif style == "exec_freemail":
        name, addr = slots["exec_name"], f"{exec_first.lower()}{exec_last.lower()}{rng.randrange(1, 99)}@freemail.example"
    elif style == "employee_freemail":
        name, addr = slots["victim_name"], f"{victim_first.lower()}.{victim_last.lower()}{rng.randrange(1, 99)}@freemail.example"
    elif style == "employee_lookalike":
        name, addr = slots["victim_name"], f"{victim_first.lower()}.{victim_last.lower()}@{_lookalike(org_dom, rng)}"
    elif style == "vendor_lookalike":
        name, addr = f"{slots['vendor_contact']} ({vendor})", f"accounts@{_lookalike(vendor_dom, rng)}"
    elif style == "vendor_freemail":
        name, addr = slots["vendor_contact"], f"{slots['vendor_contact'].split()[0].lower()}.{vendor_dom.split('.')[0]}@freemail.example"
    elif style == "internal_lookalike":
        name, addr = f"{org} {rng.choice(['IT Support', 'Helpdesk', 'HR'])}", f"support@{_lookalike(org_dom, rng)}"
    elif style == "stranger_freemail":
        name, addr = slots["stranger"], f"{slots['stranger'].replace(' ', '.').lower()}{rng.randrange(1, 999)}@freemail.example"
    else:  # pragma: no cover
        raise ValueError(style)

    paragraphs = [rng.choice(p).format(**slots) for p in tpl["body"]]
    msg = EmailMessage()
    msg["From"] = f"{name} <{addr}>"
    msg["To"] = f"{staff_first} <{staff_first.lower()}@{org_dom}>"
    msg["Subject"] = rng.choice(tpl["subjects"]).format(**slots)
    stamp = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(
        seconds=rng.randrange(0, 8 * 365 * 86400))
    msg["Date"] = format_datetime(stamp)
    msg["Message-ID"] = f"<{tpl['id']}.{idx}.{rng.randrange(10**9)}@synthetic.aipish.test>"
    msg["X-AIPISH-Synthetic"] = "true"
    msg["X-AIPISH-Template"] = tpl["id"]
    msg.set_content("\n\n".join(paragraphs) + "\n")
    return bytes(msg)


def generate(seed: int = DEFAULT_SEED, per_template: int = DEFAULT_PER_TEMPLATE,
             templates: list[dict] | None = None) -> list[RawMessage]:
    out = []
    for tpl in templates or TEMPLATES:
        rng = random.Random(f"{seed}:{tpl['id']}")
        for i in range(per_template):
            out.append(RawMessage("synthetic", "app.ml.dataset.synthetic", f"{tpl['id']}/{i:03d}",
                                  tpl["family"], _sample(tpl, i, rng), synthetic_template=tpl["id"]))
    return out
