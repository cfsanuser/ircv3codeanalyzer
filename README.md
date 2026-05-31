# ircv3codeanalyzer
Analyzes code and determines a percent and shows which feature set it is weak in.

Example:

================================================================
  IRCv3 SUPPORT ANALYZER
================================================================

  File        : eyearesee.py
  Grade       : A (VERY STRONG)
  Percentile  : 88.5%
  [##########################----]

  -- Specification-Level Coverage --
  Spec               Coverage  Bar
  ---------------- ----------  ------------------------------
  ircv3.1               93.8%  ##################--
  ircv3.2               95.0%  ###################-
  ircv3.3              100.0%  ####################
  ircv3-draft           62.5%  ############--------
  meta                 100.0%  ####################

  -- DETECTED (sorted by signal strength) --
  * SASL Authentication                [ircv3.1]      strength=16
  * Message Tags                       [ircv3.2]      strength=16
  * CAP (Capability Negotiation)       [ircv3.1]      strength=14
  * Batch                              [ircv3.2]      strength=13
  - Resume (draft)                     [ircv3-draft]  strength=13
  - Standard Replies                   [ircv3.3]      strength=12
  - Read Marker (draft)                [ircv3-draft]  strength=12
  - Channel Rename (draft)             [ircv3-draft]  strength=12
  - Multiline (draft)                  [ircv3-draft]  strength=12
  - Account Registration (draft)       [ircv3-draft]  strength=12
  - RPL_ISUPPORT (005)                 [ircv3.1]      strength=12
  - Away Notify                        [ircv3.2]      strength=11
  - Monitor                            [ircv3.2]      strength=11
  - CHGHOST                            [ircv3.2]      strength=10
  - SETNAME                            [ircv3.2]      strength=10
  - METADATA                           [ircv3.3]      strength=10
  - CHATHISTORY                        [ircv3.3]      strength=10
  - Account Notify                     [ircv3.2]      strength=9
  - Bot Mode                           [ircv3.3]      strength=9
  - Typing Indicator (draft)           [ircv3-draft]  strength=9
  - Event Playback (draft)             [ircv3-draft]  strength=9
  * IRCv3 version awareness            [meta]         strength=9
  * Server Time                        [ircv3.2]      strength=8
  - WHOX (extended WHO)                [ircv3.2]      strength=8
  - Reaction (draft)                   [ircv3-draft]  strength=7
  * CAP 302 (LS version)               [ircv3.2]      strength=7
  - WEBIRC                             [ircv3.1]      strength=7
  - Extended Join                      [ircv3.2]      strength=6
  - Echo Message                       [ircv3.2]      strength=6
  - STS (Strict Transport Security)    [ircv3.3]      strength=6
  - Invite Notify                      [ircv3.2]      strength=6
  - msgid                              [ircv3.2]      strength=6
  - Account Tag                        [ircv3.2]      strength=5
  - Multi-prefix                       [ircv3.1]      strength=5
  - Userhost-in-Names                  [ircv3.2]      strength=5
  - Labeled Response                   [ircv3.2]      strength=4
  - Reply (draft)                      [ircv3-draft]  strength=3
  - STARTTLS                           [ircv3.1]      strength=1

  -- MISSING --
  - Display Name (draft)               [ircv3-draft]
  - Relaymsg (draft)                   [ircv3-draft]
  - Channel Context (draft)            [ircv3-draft]
  - Pre-Away (draft)                   [ircv3-draft]
  - No Implicit Names (draft)          [ircv3-draft]
  - UTF8ONLY                           [ircv3.2]

  -- Top 5 Recommendations (highest-impact missing features) --
  1. Implement Display Name (draft)  [ircv3-draft]
  2. Implement Relaymsg (draft)  [ircv3-draft]
  3. Implement Channel Context (draft)  [ircv3-draft]
  4. Implement Pre-Away (draft)  [ircv3-draft]
  5. Implement No Implicit Names (draft)  [ircv3-draft]

  * = core feature (double-weighted in scoring)
