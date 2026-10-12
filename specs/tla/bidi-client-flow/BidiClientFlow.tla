--------------------------- MODULE BidiClientFlow ---------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS MaxStreams, MaxReq, MaxMsg, TAKEOVER, ROUTE, CLOSE, DETACHED

ASSUME TAKEOVER \in {"highest", "current", "latest"}
ASSUME ROUTE \in {"stream", "current", "control"}
ASSUME CLOSE \in {"check", "blind"}
ASSUME DETACHED \in {"queue", "serverstream", "drop"}

Streams == 1..MaxStreams
Control == 0

VARIABLES
    cstate,
    inq,
    started,
    ended,
    babort,
    chan,
    cur,
    handled,
    out,
    readFrom,
    sent,
    sub,
    pending,
    published,
    got,
    dropped,
    discardReq,
    discarded,
    detachedMsgs

vars == <<cstate, inq, started, ended, babort, chan, cur, handled, out, readFrom,
          sent, sub, pending, published, got, dropped, discardReq, discarded,
          detachedMsgs>>

Reply(r) == [k |-> "reply", r |-> r]
Msg(m) == [k |-> "msg", m |-> m]

TypeOK ==
    /\ cstate \in [Streams -> {"none", "open", "aborted"}]
    /\ started \in [Streams -> BOOLEAN]
    /\ ended \in [Streams -> BOOLEAN]
    /\ babort \in [Streams -> BOOLEAN]
    /\ cur \in Streams \cup {0}
    /\ handled \subseteq Streams
    /\ sub \in BOOLEAN
    /\ discardReq \in BOOLEAN
    /\ discarded \in BOOLEAN

Init ==
    /\ cstate = [s \in Streams |-> "none"]
    /\ inq = [s \in Streams |-> <<>>]
    /\ started = [s \in Streams |-> FALSE]
    /\ ended = [s \in Streams |-> FALSE]
    /\ babort = [s \in Streams |-> FALSE]
    /\ chan = <<>>
    /\ cur = 0
    /\ handled = {}
    /\ out = [s \in Streams \cup {Control} |-> <<>>]
    /\ readFrom = {}
    /\ sent = 0
    /\ sub = TRUE
    /\ pending = <<>>
    /\ published = 0
    /\ got = {}
    /\ dropped = {}
    /\ discardReq = FALSE
    /\ discarded = FALSE
    /\ detachedMsgs = {}

ClientOpen(s) ==
    /\ ~discarded
    /\ cstate[s] = "none"
    /\ \A t \in Streams : t < s => cstate[t] # "none"
    /\ cstate' = [cstate EXCEPT ![s] = "open"]
    /\ UNCHANGED <<inq, started, ended, babort, chan, cur, handled, out, readFrom,
                   sent, sub, pending, published, got, dropped, discardReq, discarded, detachedMsgs>>

ClientSend(s) ==
    /\ cstate[s] = "open"
    /\ sent < MaxReq
    /\ sent' = sent + 1
    /\ inq' = [inq EXCEPT ![s] = Append(@, sent + 1)]
    /\ UNCHANGED <<cstate, started, ended, babort, chan, cur, handled, out, readFrom,
                   sub, pending, published, got, dropped, discardReq, discarded, detachedMsgs>>

ClientAbort(s) ==
    /\ cstate[s] = "open"
    /\ cstate' = [cstate EXCEPT ![s] = "aborted"]
    /\ inq' = [inq EXCEPT ![s] = <<>>]
    /\ UNCHANGED <<started, ended, babort, chan, cur, handled, out, readFrom,
                   sent, sub, pending, published, got, dropped, discardReq, discarded, detachedMsgs>>

ClientDiscard ==
    /\ ~discarded
    /\ \E s \in Streams : cstate[s] # "none"
    /\ \A s \in Streams : cstate[s] # "open"
    /\ discarded' = TRUE
    /\ discardReq' = TRUE
    /\ UNCHANGED <<cstate, inq, started, ended, babort, chan, cur, handled, out, readFrom,
                   sent, sub, pending, published, got, dropped, detachedMsgs>>

ReaderOpen(s) ==
    /\ cstate[s] # "none"
    /\ ~started[s]
    /\ started' = [started EXCEPT ![s] = TRUE]
    /\ chan' = Append(chan, [t |-> "open", s |-> s])
    /\ UNCHANGED <<cstate, inq, ended, babort, cur, handled, out, readFrom,
                   sent, sub, pending, published, got, dropped, discardReq, discarded, detachedMsgs>>

ReaderRead(s) ==
    /\ started[s]
    /\ ~ended[s]
    /\ ~babort[s]
    /\ inq[s] # <<>>
    /\ chan' = Append(chan, [t |-> "req", s |-> s, r |-> Head(inq[s])])
    /\ readFrom' = readFrom \cup {<<s, Head(inq[s])>>}
    /\ inq' = [inq EXCEPT ![s] = Tail(@)]
    /\ UNCHANGED <<cstate, started, ended, babort, cur, handled, out,
                   sent, sub, pending, published, got, dropped, discardReq, discarded, detachedMsgs>>

ReaderEnd(s) ==
    /\ started[s]
    /\ ~ended[s]
    /\ cstate[s] = "aborted" \/ babort[s]
    /\ ended' = [ended EXCEPT ![s] = TRUE]
    /\ chan' = Append(chan, [t |-> "closed", s |-> s])
    /\ UNCHANGED <<cstate, inq, started, babort, cur, handled, out, readFrom,
                   sent, sub, pending, published, got, dropped, discardReq, discarded, detachedMsgs>>

AbortStream(b, s) == IF s = 0 THEN b ELSE [b EXCEPT ![s] = TRUE]

Highest(S) == IF S = {} THEN 0 ELSE CHOOSE x \in S : \A y \in S : y <= x

Supersedes(s) ==
    CASE TAKEOVER = "highest" -> s > Highest(handled)
      [] TAKEOVER = "current" -> s > cur
      [] TAKEOVER = "latest" -> TRUE

HandleOpen(e) ==
    /\ handled' = handled \cup {e.s}
    /\ IF Supersedes(e.s)
       THEN /\ cur' = e.s
            /\ babort' = AbortStream(babort, cur)
       ELSE /\ babort' = AbortStream(babort, e.s)
            /\ UNCHANGED cur
    /\ UNCHANGED <<out, sub, pending, got, dropped>>

ReplyTarget(e) ==
    CASE ROUTE = "stream" -> IF cur = e.s THEN e.s ELSE -1
      [] ROUTE = "current" -> IF cur # 0 THEN cur ELSE -1
      [] ROUTE = "control" -> Control

HandleReq(e) ==
    /\ LET target == ReplyTarget(e)
       IN out' = IF target = -1 THEN out
                 ELSE [out EXCEPT ![target] = Append(@, Reply(e.r))]
    /\ UNCHANGED <<cur, babort, handled, sub, pending, got, dropped>>

HandleClosed(e) ==
    /\ cur' = IF CLOSE = "blind" \/ cur = e.s THEN 0 ELSE cur
    /\ UNCHANGED <<babort, handled, out, sub, pending, got, dropped>>

Handle ==
    /\ chan # <<>>
    /\ chan' = Tail(chan)
    /\ LET e == Head(chan)
       IN CASE e.t = "open" -> HandleOpen(e)
            [] e.t = "req" -> HandleReq(e)
            [] e.t = "closed" -> HandleClosed(e)
    /\ UNCHANGED <<cstate, inq, started, ended, readFrom, sent, published,
                   discardReq, discarded, detachedMsgs>>

HandleDiscard ==
    /\ discardReq
    /\ discardReq' = FALSE
    /\ sub' = FALSE
    /\ pending' = <<>>
    /\ cur' = 0
    /\ babort' = AbortStream(babort, cur)
    /\ UNCHANGED <<cstate, inq, started, ended, chan, handled, out, readFrom,
                   sent, published, got, dropped, discarded, detachedMsgs>>

Publish ==
    /\ sub
    /\ published < MaxMsg
    /\ published' = published + 1
    /\ pending' = Append(pending, published + 1)
    /\ detachedMsgs' = IF cur = 0 /\ handled # {} THEN detachedMsgs \cup {published + 1} ELSE detachedMsgs
    /\ UNCHANGED <<cstate, inq, started, ended, babort, chan, cur, handled, out, readFrom,
                   sent, sub, got, dropped, discardReq, discarded>>

DeliverOnFlow ==
    /\ pending # <<>>
    /\ cur # 0
    /\ ~babort[cur]
    /\ cstate[cur] = "open"
    /\ out' = [out EXCEPT ![cur] = Append(@, Msg(Head(pending)))]
    /\ got' = got \cup {Head(pending)}
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<cstate, inq, started, ended, babort, chan, cur, handled, readFrom,
                   sent, sub, published, dropped, discardReq, discarded, detachedMsgs>>

DeliverDetached ==
    /\ pending # <<>>
    /\ cur = 0
    /\ DETACHED # "queue"
    /\ pending' = Tail(pending)
    /\ IF DETACHED = "serverstream"
       THEN /\ out' = [out EXCEPT ![Control] = Append(@, Msg(Head(pending)))]
            /\ got' = got \cup {Head(pending)}
            /\ UNCHANGED dropped
       ELSE /\ dropped' = dropped \cup {Head(pending)}
            /\ UNCHANGED <<out, got>>
    /\ UNCHANGED <<cstate, inq, started, ended, babort, chan, cur, handled, readFrom,
                   sent, sub, published, discardReq, discarded, detachedMsgs>>

BrokerNext ==
    \/ \E s \in Streams : ReaderOpen(s) \/ ReaderRead(s) \/ ReaderEnd(s)
    \/ Handle
    \/ HandleDiscard
    \/ DeliverOnFlow
    \/ DeliverDetached

ClientNext ==
    \/ \E s \in Streams : ClientOpen(s) \/ ClientSend(s) \/ ClientAbort(s)
    \/ ClientDiscard
    \/ Publish

Next == BrokerNext \/ ClientNext

Spec == Init /\ [][Next]_vars

Quiescent == ~ENABLED BrokerNext

NewestLive(s) ==
    /\ cstate[s] = "open"
    /\ ~babort[s]
    /\ \A t \in Streams : t > s => cstate[t] = "none"

ReplyOnOwnStream ==
    \A s \in Streams : \A i \in 1..Len(out[s]) :
        out[s][i].k = "reply" => <<s, out[s][i].r>> \in readFrom

NothingOffFlow == out[Control] = <<>>

CurrentIsNewest == cur # 0 => cur = Highest(handled)

NewestLiveIsCurrentWhenQuiet ==
    Quiescent => \A s \in Streams : NewestLive(s) => cur = s

AnsweredWhenQuiet ==
    Quiescent => \A s \in Streams : NewestLive(s) =>
        \A p \in readFrom : p[1] = s =>
            \E i \in 1..Len(out[s]) : out[s][i] = Reply(p[2])

DeliveredWhenQuiet ==
    Quiescent => ((\E s \in Streams : NewestLive(s)) => pending = <<>>)

NoSilentDrop == dropped = {}

NEG_TakeoverDelivers ==
    ~(\E s \in Streams : s > 1 /\ babort[s - 1] /\ \E i \in 1..Len(out[s]) : out[s][i].k = "msg")

NEG_RecoveryDelivers == ~(\E s \in Streams : s > 1 /\ \E i \in 1..Len(out[s]) : out[s][i].k = "msg" /\ out[s][i].m \in detachedMsgs /\ cstate[s - 1] = "aborted")

=============================================================================
