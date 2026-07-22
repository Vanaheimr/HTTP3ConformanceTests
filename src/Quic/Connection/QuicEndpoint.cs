/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using org.GraphDefined.Vanaheimr.Hermod.Quic.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Frames;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Packets;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Recovery;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Streams;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Crypto;
using org.GraphDefined.Vanaheimr.Hermod.Quic.Tls.Handshake;
using System.Diagnostics;
using System.Security.Cryptography;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.Quic.Connection;

/// <summary>
/// Gemeinsame Basis von <see cref="QuicClientConnection"/> und <see cref="QuicServerConnection"/>:
/// Encryption-Levels, Packet-Number-Spaces, CRYPTO-Reassemblierung, Schlüsselinstallation, Streams,
/// Flow Control und Loss Recovery – alles richtungsunabhängig. Die Rollenunterschiede (Schlüssel-
/// richtung, Connection-ID-Vergabe, Stream-Perspektive, HANDSHAKE_DONE) sind über <see cref="IsServer"/>
/// und die überschreibbaren Hooks abgebildet.
/// </summary>
public abstract class QuicEndpoint : IDisposable
{
    protected const int LevelCount = 3;

    protected readonly uint Version;
    protected readonly TransportParameters LocalParams;
    protected ConnectionId Scid;
    protected ConnectionId Dcid;

    /// <summary>
    /// Die TLS-Engine dieser Rolle. Beim Server erst nach dem ersten Client-Initial gesetzt.
    /// </summary>
    protected ITlsHandshake? TlsHandshake;

    protected readonly PacketProtection?[] WriteKeys = new PacketProtection?[LevelCount];
    protected readonly PacketProtection?[] ReadKeys = new PacketProtection?[LevelCount];
    protected readonly PacketNumberSpace[] Spaces = [new(), new(), new()];
    protected readonly Dictionary<ulong, QuicStream> StreamMap = [];
    protected TransportParameters? PeerParams;

    private readonly CryptoStreamAssembler[] _recvCrypto = [new(), new(), new()];
    private readonly long[] _deliveredCrypto = new long[LevelCount];
    private readonly ulong[] _sendCryptoOffset = new ulong[LevelCount];
    private readonly List<byte>[] _outgoingCrypto = [[], [], []]; // noch zu sendende CRYPTO je Level (bleibt gepuffert, bis gesendet)
    private bool _handshakeKeysInstalled;
    private bool _appKeysInstalled;

    // Verwerfen der Initial-/Handshake-Schlüssel nach dem Handshake (RFC 9001 §4.9.1/§4.9.2), damit danach
    // KEINE Initial-/Handshake-Pakete mehr gesendet werden (sonst sondiert ein PTO fälschlich diese Spaces).
    private bool _initialKeysDiscarded;
    private bool _handshakeKeysDiscarded;
    private bool _handshakePacketSent;      // Client: hat ≥1 Handshake-Paket gesendet
    private bool _handshakePacketReceived;  // Server: hat ≥1 Handshake-Paket verarbeitet
    private ulong? _firstOneRttPacketNumber; // PN des ersten mit 1-RTT-Keys gesendeten Pakets (RFC 9001 §4.1.2)

    // 0-RTT (RFC 9001 §4): eigener Schlüsselsatz aus dem client_early_traffic_secret. Nur Client→Server, daher
    // beim Client der Schreib-, beim Server der Leseschlüssel; die Pakete laufen im Application-Packet-Number-Space.
    private PacketProtection? _zeroRttKeys;
    private bool _zeroRttInstalled;
    private bool _zeroRttDataSent;         // Client: es wurden 0-RTT-Pakete gesendet
    private ulong _zeroRttMaxPacketNumber; // höchste als 0-RTT gesendete PN (Grenze zu 1-RTT)
    private bool _zeroRttRejectionHandled;
    // Server: Deadline (Ticks), zu der die 0-RTT-Read-Keys nach dem ersten 1-RTT-Paket verworfen werden
    // (RFC 9001 §4.9.3, RECOMMENDED 3×PTO). −1 = noch nicht scharfgeschaltet.
    private long _serverZeroRttDiscardDeadlineTicks = -1;
    private bool _serverOneRttPacketReceived; // Server: hat ≥1 echtes 1-RTT-Paket empfangen (Obergrenze der 0-RTT-PNs bekannt)

    // Anti-Amplification (RFC 9000 §8.1): vor Adressvalidierung darf der Server höchstens 3× so viele Bytes
    // senden, wie er empfangen hat. Für den Client ist die Adresse per Konstruktion validiert.
    private long _amplificationReceived;
    private long _amplificationSent;
    private bool _addressValidated;

    // 1-RTT-Key-Update (RFC 9001 §6): aktuelle Traffic Secrets, Key-Phase je Richtung und die für die
    // Gegenrichtung vorbereiteten „nächsten" Read-Keys (sowie die kurz aufbewahrten vorigen für Reordering).
    private TrafficKeys? _appWriteTk;
    private TrafficKeys? _appReadTk;
    private TrafficKeys? _nextAppReadTk;
    private PacketProtection? _nextAppReadKeys;
    private PacketProtection? _prevAppReadKeys;
    private System.Security.Cryptography.HashAlgorithmName _appHash;
    private int _appHashLength;
    private AeadAlgorithm _appAead; // AEAD der ausgehandelten Suite (AES-GCM oder ChaCha20-Poly1305)
    private bool _sendKeyPhase;
    private bool _recvKeyPhase;
    private uint _keyUpdateCount;

    private ulong _nextLocalBidiIndex;
    private ulong _nextLocalUniIndex;
    private ulong _connSendUsed;
    private ulong _connSendLimit;
    private ulong _localConnMaxData;

    private readonly LossRecovery _recovery = new();
    private readonly Pacer _pacer = new();
    private readonly IdleTimeout _idle = new();
    private bool _idleTimedOut;
    private TimeSpan? _keepAliveInterval; // Keep-Alive-PING-Intervall (RFC 9000 §10.1.2); null = aus
    private bool _pingPending;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly List<Frame>[] _retransmitQueue = [[], [], []];
    private readonly Queue<byte[]> _pendingDatagrams = new(); // Rohdatagramme (Version Negotiation / Retry)
    private bool _anyPacketProcessed;

    private ConnectionState _state = ConnectionState.Active;
    private ConnectionCloseFrame? _closeFrame;   // das eigene CONNECTION_CLOSE (im Closing-Zustand)
    private bool _closePacketPending;            // ob (erneut) ein Close-Paket zu senden ist
    private long _closeDeadlineTicks = -1;       // Ende der Closing-/Draining-Periode

    private readonly ConnectionIdManager _cids;  // Connection-ID-Verwaltung (RFC 9000 §5.1)

    /// <summary>
    /// Optionaler Generator für aus der CID ableitbare Stateless-Reset-Tokens (RFC 9000 §10.3.1). Ist er gesetzt
    /// (Server), werden ausgegebene Tokens per HMAC aus der CID gebildet und sind so nach Zustandsverlust
    /// nachrechenbar, was das Senden eines Stateless Reset überhaupt erst ermöglicht.
    /// </summary>
    protected StatelessResetTokenGenerator? StatelessResetTokens { get; set; }
    private readonly List<Frame> _pendingControlFrames = []; // ausstehende Kontrollframes (NEW_/RETIRE_CONNECTION_ID, PATH_CHALLENGE/RESPONSE)
    private ulong? _pathChallengePending; // die von uns gesendeten 8 PATH_CHALLENGE-Bytes, solange offen (RFC 9000 §8.2)
    private long _pathValidationDeadlineTicks = -1;

    /// <summary>
    /// Retry-Token, das dem nächsten Initial beigelegt wird (leer, solange kein Retry empfangen wurde).
    /// </summary>
    protected byte[] InitialToken = [];

    /// <summary>
    /// Verbindungszustand (RFC 9000 §10.2): aktiv, schließend, entleerend oder geschlossen.
    /// </summary>
    private enum ConnectionState { Active, Closing, Draining, Closed }

    protected QuicEndpoint(TransportParameters? transportParameters, uint version)
    {
        Version = version;
        LocalParams = transportParameters ?? new TransportParameters();
        _localConnMaxData = LocalParams.InitialMaxDataValue;
        Scid = new ConnectionId(RandomNumberGenerator.GetBytes(8));
        _cids = new ConnectionIdManager(Scid); // lokale Handshake-CID = Sequenz 0
        _addressValidated = !IsServer;         // der Client sieht die Server-Adresse als validiert an
        _idle.Negotiate(LocalParams.MaxIdleTimeoutMs, peerMs: 0); // Peer-Wert folgt nach dem Handshake
        _idle.Start(_clock.Elapsed.Ticks);
    }

    /// <summary>
    /// <c>true</c> für die Server-Rolle. Steuert Schlüsselrichtung und Stream-Perspektive.
    /// </summary>
    protected abstract bool IsServer { get; }

    public ConnectionId SourceConnectionId => Scid;
    public IReadOnlyDictionary<ulong, QuicStream> Streams => StreamMap;
    public TransportParameters? PeerTransportParameters => PeerParams;

    /// <summary>
    /// Aktuelles Congestion Window in Bytes (RFC 9002 §7). Diagnose.
    /// </summary>
    public long CongestionWindow => _recovery.Congestion.CongestionWindow;

    /// <summary>
    /// Aktuell unbestätigte, congestion-kontrollierte Bytes im Flug. Diagnose.
    /// </summary>
    public long BytesInFlight => _recovery.Congestion.BytesInFlight;

    /// <summary>
    /// Anzahl im Application-Space empfangener CE-markierter Pakete (RFC 9000 §13.4). Diagnose/Test.
    /// </summary>
    public ulong ApplicationReceivedCeCount => Spaces[(int)EncryptionLevel.Application].ReceivedCeCount;

    /// <summary>
    /// <c>true</c>, sobald die Verbindung wegen Idle-Timeout still geschlossen wurde (RFC 9000 §10.1).
    /// </summary>
    public bool IsIdleTimedOut => _idleTimedOut;

    /// <summary>
    /// Keep-Alive-Intervall (RFC 9000 §10.1.2): Ist es gesetzt, sendet die Verbindung nach so viel
    /// Inaktivität ein PING, um den Idle-Timeout auf beiden Seiten zurückzusetzen. Sollte deutlich kleiner
    /// als der ausgehandelte Idle-Timeout sein. <c>null</c> = deaktiviert.
    /// </summary>
    public TimeSpan? KeepAliveInterval
    {
        get => _keepAliveInterval;
        set => _keepAliveInterval = value;
    }

    // ---- Connection-ID-Rotation (RFC 9000 §5.1) --------------------------------------------

    /// <summary>
    /// Anzahl aktiver, von uns ausgegebener Connection IDs (die der Peer als DCID nutzen darf).
    /// </summary>
    public int LocalConnectionIdCount => _cids.LocalCount;

    /// <summary>
    /// Anzahl bekannter, vom Peer ausgegebener Connection IDs (die wir als DCID nutzen können).
    /// </summary>
    public int RemoteConnectionIdCount => _cids.RemoteCount;

    /// <summary>
    /// Aktuell zum Senden genutzte Destination Connection ID.
    /// </summary>
    public ConnectionId DestinationConnectionId => Dcid;

    /// <summary>
    /// Gibt dem Peer per NEW_CONNECTION_ID (RFC 9000 §19.15) eine zusätzliche Connection ID (8 Byte) samt
    /// Stateless-Reset-Token, sofern dessen <c>active_connection_id_limit</c> es zulässt. Erfordert
    /// installierte 1-RTT-Schlüssel. Gibt die neue ID zurück oder <c>null</c>, wenn nichts ausgegeben wurde.
    /// </summary>
    public ConnectionId? IssueConnectionId()
    {
        if (!_appKeysInstalled)
            return null;
        var newCid = new ConnectionId(RandomNumberGenerator.GetBytes(8));
        // Token aus der CID ableiten (falls ein Generator gesetzt ist), damit es nach Zustandsverlust für einen
        // Stateless Reset neu berechenbar bleibt; sonst zufällig.
        byte[] token = StatelessResetTokens?.ComputeToken(newCid.Span) ?? RandomNumberGenerator.GetBytes(16);
        ulong limit = PeerParams?.ActiveConnectionIdLimitValue ?? 2;
        if (_cids.Issue(newCid, token, limit) is not { } frame)
            return null;
        _pendingControlFrames.Add(frame);
        return newCid;
    }

    /// <summary>
    /// Wechselt die Destination Connection ID auf eine zuvor vom Peer angebotene (RFC 9000 §5.1) und zieht
    /// die bisherige per RETIRE_CONNECTION_ID zurück. Gibt <c>true</c> zurück, wenn eine weitere ID verfügbar war.
    /// </summary>
    public bool RotateDestinationConnectionId()
    {
        if (_cids.Rotate() is not { } rotation)
            return false;
        Dcid = rotation.NewDcid;
        _pendingControlFrames.Add(rotation.Retire);
        return true;
    }

    /// <summary>
    /// <c>true</c>, wenn <paramref name="cid"/> eine unserer aktiven lokalen Connection IDs ist (für CID-basiertes Demuxing).
    /// </summary>
    public bool OwnsConnectionId(ConnectionId cid) => _cids.IsLocalConnectionId(cid);

    // ---- Pfadvalidierung / Connection Migration (RFC 9000 §8.2, §9) -------------------------

    /// <summary>
    /// Es läuft eine Pfadvalidierung (PATH_CHALLENGE gesendet, PATH_RESPONSE ausstehend).
    /// </summary>
    public bool PathValidationPending => _pathChallengePending is not null;

    /// <summary>
    /// <c>true</c>, sobald die letzte Pfadvalidierung mit passendem PATH_RESPONSE bestätigt wurde.
    /// </summary>
    public bool PathValidated { get; private set; }

    /// <summary>
    /// Startet eine Pfadvalidierung (RFC 9000 §8.2): sendet ein PATH_CHALLENGE mit 8 zufälligen Bytes und
    /// erwartet ein passendes PATH_RESPONSE. Grundlage jeder Connection Migration (RFC 9000 §9) – der neue
    /// Pfad gilt erst nach erfolgreicher Validierung als erreichbar.
    /// </summary>
    public void InitiatePathValidation()
    {
        ulong data = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        _pathChallengePending = data;
        PathValidated = false;
        _pendingControlFrames.Add(new PathChallengeFrame(data));
        _pathValidationDeadlineTicks = _clock.Elapsed.Ticks + (3 * _recovery.Rtt.GetProbeTimeout(_recovery.MaxAckDelay)).Ticks;
    }

    /// <summary>
    /// <c>true</c>, während wir nach einem eigenen CONNECTION_CLOSE im Closing-Zustand sind (RFC 9000 §10.2.1).
    /// </summary>
    public bool IsClosing => _state == ConnectionState.Closing;

    /// <summary>
    /// <c>true</c>, während wir nach einem empfangenen CONNECTION_CLOSE im Draining-Zustand sind (§10.2.2).
    /// </summary>
    public bool IsDraining => _state == ConnectionState.Draining;

    /// <summary>
    /// <c>true</c>, sobald die Closing-/Draining-Periode (3·PTO) abgelaufen und die Verbindung endgültig zu ist.
    /// </summary>
    public bool IsClosed => _state == ConnectionState.Closed;

    /// <summary>
    /// Das vom Peer empfangene CONNECTION_CLOSE (Fehlercode + Grund), falls vorhanden.
    /// </summary>
    public ConnectionCloseFrame? PeerCloseFrame { get; private set; }

    /// <summary>
    /// <c>true</c>, wenn ein Stateless Reset des Peers erkannt wurde (RFC 9000 §10.3). Führt in Draining.
    /// </summary>
    public bool StatelessResetReceived { get; private set; }

    /// <summary>
    /// Schließt die Verbindung sofort (RFC 9000 §10.2): sendet ein CONNECTION_CLOSE (Transport-Fehler
    /// <paramref name="error"/>, Standard NO_ERROR = anständiger Abbau) und geht in den Closing-Zustand.
    /// Danach werden nur noch CONNECTION_CLOSE-Pakete gesendet, bis nach 3·PTO der Closed-Zustand folgt.
    /// </summary>
    public void Close(TransportError error = TransportError.NoError, string reason = "")
    {
        if (_state != ConnectionState.Active)
            return;
        _closeFrame = ConnectionCloseFrame.Transport(error, reason);
        _state = ConnectionState.Closing;
        _closePacketPending = true;
        _closeDeadlineTicks = _clock.Elapsed.Ticks + CloseTimeout().Ticks;
    }

    /// <summary>
    /// Closing-/Draining-Dauer nach RFC 9000 §10.2: dreimal der aktuelle Probe Timeout.
    /// </summary>
    private TimeSpan CloseTimeout() => 3 * _recovery.Rtt.GetProbeTimeout(_recovery.MaxAckDelay);

    /// <summary>
    /// Nach Ablauf der Closing-/Draining-Periode in den endgültigen Closed-Zustand wechseln.
    /// </summary>
    private void MaybeTransitionToClosed()
    {
        if (_state is ConnectionState.Closing or ConnectionState.Draining &&
            _closeDeadlineTicks >= 0 && _clock.Elapsed.Ticks >= _closeDeadlineTicks)
            _state = ConnectionState.Closed;
    }

    /// <summary>
    /// Prüft den Idle-Timeout (RFC 9000 §10.1). Bei Ablauf wird die Verbindung still geschlossen
    /// (Zustand verworfen): danach werden keine Datagramme mehr erzeugt oder verarbeitet. Periodisch
    /// aufrufen. Gibt <c>true</c> zurück, sobald der Timeout eingetreten ist.
    /// </summary>
    public bool CheckIdleTimeout()
    {
        MaybeTransitionToClosed(); // Closing/Draining nach 3·PTO abschließen (RFC 9000 §10.2)

        // Pfadvalidierung ohne Antwort verfällt (RFC 9000 §8.2): PathValidated bleibt dann false.
        if (_pathChallengePending is not null && _pathValidationDeadlineTicks >= 0 &&
            _clock.Elapsed.Ticks >= _pathValidationDeadlineTicks)
        {
            _pathChallengePending = null;
            _pathValidationDeadlineTicks = -1;
        }
        if (!_idleTimedOut &&
            _idle.IsExpired(_clock.Elapsed.Ticks, _recovery.Rtt.GetProbeTimeout(_recovery.MaxAckDelay)))
            _idleTimedOut = true;
        return _idleTimedOut;
    }

    // ---- Rollen-Hooks (Standard: kein Verhalten) -------------------------------------------

    /// <summary>
    /// Wird für jedes empfangene Long-Header-Paket vor der Entschlüsselung aufgerufen.
    /// </summary>
    protected virtual void OnLongHeaderPacket(LongPacketType type, LongHeaderPrefix prefix) { }

    /// <summary>
    /// Fügt vor den übrigen 1-RTT-Frames rollen­spezifische Kontrollframes ein (Server: HANDSHAKE_DONE).
    /// </summary>
    protected virtual void AddApplicationControlFrames(List<Frame> frames) { }

    /// <summary>
    /// Ein HANDSHAKE_DONE wurde empfangen (nur der Client reagiert darauf).
    /// </summary>
    protected virtual void OnHandshakeDoneReceived() { }

    /// <summary>
    /// Eines unserer 1-RTT-Pakete wurde bestätigt. Der Client DARF den Handshake daraufhin als bestätigt ansehen
    /// (RFC 9001 §4.1.2), auch ohne HANDSHAKE_DONE. Der Server nutzt das nicht (er bestätigt beim Abschluss).
    /// </summary>
    protected virtual void OnOneRttPacketAcknowledged() { }

    /// <summary>
    /// Ein 1-RTT-Frame wurde verarbeitet (Client: für Inspektion sammeln).
    /// </summary>
    protected virtual void OnApplicationFrameHandled(Frame frame) { }

    /// <summary>
    /// Ein Stream wurde (ggf. neu) beliefert (Server: neue Request-Streams verfolgen).
    /// </summary>
    protected virtual void OnStreamOpened(StreamId id, bool isNew) { }

    /// <summary>
    /// Ein Version-Negotiation-Paket wurde empfangen (nur der Client reagiert darauf).
    /// </summary>
    protected virtual void HandleVersionNegotiationPacket(ReadOnlySpan<byte> datagram) { }

    /// <summary>
    /// Ein Retry-Paket wurde empfangen (nur der Client reagiert darauf).
    /// </summary>
    protected virtual void HandleRetryPacket(ReadOnlySpan<byte> datagram) { }

    /// <summary>
    /// Ein Long-Header-Paket mit nicht unterstützter Version kam an (nur der Server reagiert – mit VN).
    /// </summary>
    protected virtual void HandleUnsupportedVersion(ReadOnlySpan<byte> datagram) { }

    /// <summary>
    /// Reiht ein bereits fertiges Rohdatagramm (Version Negotiation / Retry) zum Senden ein.
    /// </summary>
    protected void EnqueueDatagram(byte[] datagram) => _pendingDatagrams.Enqueue(datagram);

    /// <summary>
    /// Markiert die Peer-Adresse als validiert (RFC 9000 §8.1) – z. B. nachdem ein gültiges Retry-Token
    /// zurückkam. Hebt das Anti-Amplification-Limit auf.
    /// </summary>
    protected void MarkAddressValidated() => _addressValidated = true;

    /// <summary>
    /// <c>true</c>, sobald die Peer-Adresse validiert ist (kein Anti-Amplification-Limit mehr). Diagnose.
    /// </summary>
    public bool AddressValidated => _addressValidated;

    /// <summary>
    /// <c>true</c>, sobald mindestens ein Paket erfolgreich verarbeitet wurde (für die VN-Regeln, RFC 9000 §6.2).
    /// </summary>
    protected bool AnyPacketProcessed => _anyPacketProcessed;

    /// <summary>
    /// Reagiert clientseitig auf einen Retry: neue Initial-Schlüssel aus <paramref name="newDcid"/> ableiten
    /// (RFC 9001 §5.2), Retry-Token merken und den Initial-CRYPTO-Offset zurücksetzen, damit der ClientHello
    /// erneut ab Offset 0 gesendet wird.
    /// </summary>
    protected void ApplyRetry(ConnectionId newDcid, byte[] token)
    {
        Dcid = newDcid;
        InitialToken = token;
        InstallInitialKeys(newDcid);
        _sendCryptoOffset[(int)EncryptionLevel.Initial] = 0;
    }

    // ---- Öffnen von Streams ----------------------------------------------------------------

    protected QuicStream OpenLocalStream(bool bidirectional)
    {
        MaybeDecodePeerParameters();
        ulong index = bidirectional ? _nextLocalBidiIndex++ : _nextLocalUniIndex++;
        return GetOrCreateStream(StreamId.Create(clientInitiated: !IsServer, bidirectional, index));
    }

    private QuicStream GetOrCreateStream(StreamId id)
    {
        if (StreamMap.TryGetValue(id.Value, out QuicStream? existing))
            return existing;
        var stream = new QuicStream(id, PeerSendLimitFor(id), ReceiveWindowFor(id));
        StreamMap[id.Value] = stream;
        return stream;
    }

    // "Lokal initiiert" aus Sicht dieser Rolle (Client: client-initiiert, Server: server-initiiert).
    private bool LocallyInitiated(StreamId id) => IsServer ? id.IsServerInitiated : id.IsClientInitiated;

    private ulong ReceiveWindowFor(StreamId id)
        => id.IsUnidirectional
            ? LocalParams.InitialMaxStreamDataUniValue
            : LocallyInitiated(id)
                ? LocalParams.InitialMaxStreamDataBidiLocalValue
                : LocalParams.InitialMaxStreamDataBidiRemoteValue;

    private ulong PeerSendLimitFor(StreamId id)
    {
        if (PeerParams is null)
            return 0;
        return id.IsUnidirectional
            ? PeerParams.InitialMaxStreamDataUniValue
            : LocallyInitiated(id)
                ? PeerParams.InitialMaxStreamDataBidiRemoteValue
                : PeerParams.InitialMaxStreamDataBidiLocalValue;
    }

    // ---- Senden ----------------------------------------------------------------------------

    /// <summary>
    /// Erzeugt die aktuell zu sendenden Datagramme (CRYPTO, ACKs, Stream-Daten, Flow Control).
    /// </summary>
    public IReadOnlyList<byte[]> GetDatagramsToSend()
    {
        var datagrams = new List<byte[]>();
        MaybeTransitionToClosed();
        if (_idleTimedOut || _state is ConnectionState.Draining or ConnectionState.Closed)
            return datagrams; // im Draining/Closed nichts senden (RFC 9000 §10.2.2)

        // Im Closing-Zustand ausschließlich (wiederholt) das CONNECTION_CLOSE senden (RFC 9000 §10.2.1).
        if (_state == ConnectionState.Closing)
        {
            if (_closePacketPending && BuildClosePacket() is { } closePacket)
            {
                _closePacketPending = false;
                datagrams.Add(closePacket);
            }
            return datagrams;
        }

        // Rohdatagramme (Version Negotiation / Retry) vorab senden – unabhängig vom TLS-Zustand.
        while (_pendingDatagrams.Count > 0)
            datagrams.Add(_pendingDatagrams.Dequeue());
        if (TlsHandshake is null)
            return datagrams;

        // Keep-Alive (RFC 9000 §10.1.2): nach genug Inaktivität ein PING einplanen, das den Idle-Timeout
        // beidseitig zurücksetzt (das PING ist ack-eliciting und wird vom Peer bestätigt).
        if (_keepAliveInterval is { } keepAlive && _appKeysInstalled &&
            _idle.ShouldSendKeepAlive(_clock.Elapsed.Ticks, keepAlive))
            _pingPending = true;

        // Pacing-Budget für diesen Aufruf anhand der verstrichenen Zeit und der aktuellen Rate nachfüllen.
        _pacer.Refill(_clock.Elapsed.Ticks, _recovery.Congestion.CongestionWindow, _recovery.Rtt.SmoothedRtt);

        // Ausgehende CRYPTO in die persistenten Puffer übernehmen (bleibt erhalten, falls das
        // Anti-Amplification-Budget das Senden zurückstellt).
        while (TlsHandshake.TryGetOutgoingCrypto(out EncryptionLevel level, out byte[] data))
            _outgoingCrypto[(int)level].AddRange(data);

        // Anti-Amplification-Budget (RFC 9000 §8.1): unbegrenzt, sobald die Adresse validiert ist.
        long amplificationBudget = _addressValidated ? long.MaxValue : Math.Max(0, 3 * _amplificationReceived - _amplificationSent);

        MaybeInstallZeroRttKeys();      // Client: Early-Secret steht schon nach Start bereit
        MaybeHandleZeroRttRejection();  // abgelehntes 0-RTT sofort über 1-RTT nachholen

        AppendLevelPackets(EncryptionLevel.Initial, datagrams, ref amplificationBudget);
        AppendLevelPackets(EncryptionLevel.Handshake, datagrams, ref amplificationBudget);
        BuildZeroRttPackets(datagrams);     // Client: früh gequeuete Anwendungsdaten als 0-RTT (vor 1-RTT-Keys)
        BuildApplicationPackets(datagrams); // 1-RTT erst nach dem Handshake ⇒ Adresse dann bereits validiert

        // Nach dem gerade gebauten Flight die nicht mehr benötigten Schlüssel verwerfen (RFC 9001 §4.9):
        // Initial, sobald der Client sein Handshake-Paket gesendet hat; Handshake, sobald der Handshake bestätigt ist.
        MaybeDiscardInitialKeys();
        MaybeDiscardHandshakeKeys();
        MaybeDiscardServerZeroRttKeys();

        return datagrams;
    }

    /// <summary>
    /// CRYPTO-Nutzlast pro Initial-/Handshake-Paket. Konservativ gewählt, damit Header (Long Header + ggf.
    /// Token), ein evtl. mitgesendeter ACK und der AEAD-Tag zusammen die ~1200-Byte-MTU nicht sprengen –
    /// große ClientHellos (PQ-Hybrid) oder Zertifikatsketten werden so über mehrere Pakete verteilt.
    /// </summary>
    private const int MaxCryptoDataPerPacket = 1000;

    /// <summary>
    /// Emittiert die Pakete eines Encryption-Levels (RFC 9000 §12.2/§13). Passt die ausgehende CRYPTO nicht in
    /// ein MTU-großes Paket, wird sie offset-korrekt über mehrere Pakete (mehrere Initials/Handshakes)
    /// aufgeteilt. Anti-Amplification (RFC 9000 §8.1) wird pro Paket geprüft; noch nicht gesendete CRYPTO bleibt
    /// gepuffert, der Offset rückt nur um die tatsächlich gesendeten Bytes vor.
    /// </summary>
    private void AppendLevelPackets(EncryptionLevel level, List<byte[]> datagrams, ref long amplificationBudget)
    {
        int i = (int)level;
        if (WriteKeys[i] is not { } keys)
            return;

        bool firstPacket = true;
        while (true)
        {
            var frames = new List<Frame>();
            // ACK und Retransmits nur ins erste Paket dieses Levels – die Folgepakete tragen reine CRYPTO-Fortsetzung.
            if (firstPacket)
            {
                DrainRetransmitQueue(i, frames);
                if (Spaces[i].AckPending && Spaces[i].BuildAck() is { } ack)
                    frames.Add(ack);
            }

            // CRYPTO-Block so bemessen, dass er zusammen mit bereits enthaltenen Frames unter dem Paketbudget bleibt.
            int usedBytes = frames.Count > 0 ? FrameParser.Serialize(frames).Length : 0;
            int cryptoBudget = MaxCryptoDataPerPacket - usedBytes;
            int cryptoChunk = cryptoBudget > 0 ? Math.Min(_outgoingCrypto[i].Count, cryptoBudget) : 0;
            if (cryptoChunk > 0)
                frames.Add(new CryptoFrame(_sendCryptoOffset[i], _outgoingCrypto[i].GetRange(0, cryptoChunk).ToArray()));

            if (frames.Count == 0)
                return;

            ulong pn = Spaces[i].NextPacketNumber();
            int pnLength = PacketNumber.EncodeLength(pn, Spaces[i].LargestAckedByPeer);
            byte[] payload = FrameParser.Serialize(frames);

            byte[] packet = level == EncryptionLevel.Initial
                ? InitialPacketFactory.BuildPadded(keys, Version, Dcid, Scid, InitialToken, pn, pnLength, payload)
                : LongHeader.Build(keys, LongPacketType.Handshake, Version, Dcid, Scid, default, pn, pnLength, payload);

            // Anti-Amplification (RFC 9000 §8.1): sprengt das Paket das Budget, zurückstellen – die CRYPTO bleibt
            // gepuffert, der Offset unverändert (späterer Empfang hebt das Limit an).
            if (packet.Length > amplificationBudget)
                return;

            amplificationBudget -= packet.Length;
            if (!_addressValidated)
                _amplificationSent += packet.Length;
            if (cryptoChunk > 0)
            {
                _sendCryptoOffset[i] += (ulong)cryptoChunk;
                _outgoingCrypto[i].RemoveRange(0, cryptoChunk);
            }
            RecordSent(i, pn, packet.Length, frames);
            datagrams.Add(packet);
            if (level == EncryptionLevel.Handshake)
                _handshakePacketSent = true; // Client: löst später das Verwerfen der Initial-Keys aus (RFC 9001 §4.9.1)

            firstPacket = false;
            if (_outgoingCrypto[i].Count == 0)
                return; // keine weitere CRYPTO zu verteilen
        }
    }

    /// <summary>
    /// Nutzlast-Budget für Stream-Daten pro 1-RTT-Paket, damit ein Datagramm die MTU (~1200) einhält.
    /// </summary>
    private const int MaxStreamDataPerPacket = 1000;

    /// <summary>
    /// Emittiert die 1-RTT-Datagramme: ein erstes Paket mit Kontroll-/ACK-/Flow-Control-Frames (und ggf.
    /// ersten Stream-Daten), danach je ein MTU-großes Paket pro Stream-Chunk – solange cwnd (RFC 9002 §7)
    /// und Pacing (§7.7) es zulassen. Reine ACK-/Kontrollframes und PTO-Probes (Retransmit-Queue) sind vom
    /// Budget ausgenommen, damit Rückmeldungen und Verlust-Sondierungen nie blockiert werden.
    /// </summary>
    private void BuildApplicationPackets(List<byte[]> datagrams)
    {
        int i = (int)EncryptionLevel.Application;
        if (WriteKeys[i] is not { } keys)
            return;

        MaybeDecodePeerParameters();

        // Gemeinsames Budget für NEUE Stream-Daten aus Congestion Window und Pacing.
        long sendBudget = Math.Min(_recovery.Congestion.Available, _pacer.AvailableBytes);
        bool firstPacket = true;

        while (true)
        {
            var frames = new List<Frame>();
            if (firstPacket)
            {
                DrainRetransmitQueue(i, frames);
                AddApplicationControlFrames(frames); // Server: HANDSHAKE_DONE
                if (_pendingControlFrames.Count > 0)
                {
                    frames.AddRange(_pendingControlFrames); // NEW_/RETIRE_CONNECTION_ID (RFC 9000 §5.1)
                    _pendingControlFrames.Clear();
                }
                if (_pingPending)
                {
                    frames.Add(PingFrame.Instance); // Keep-Alive (RFC 9000 §10.1.2)
                    _pingPending = false;
                }
                if (Spaces[i].AckPending && Spaces[i].BuildAck() is { } ack)
                    frames.Add(ack);
                CollectFlowControlFrames(frames);

                // Post-Handshake-CRYPTO auf Application-Level (z. B. NewSessionTicket, RFC 8446 §4.6.1).
                int appCryptoChunk = Math.Min(_outgoingCrypto[i].Count, MaxCryptoDataPerPacket);
                if (appCryptoChunk > 0)
                {
                    frames.Add(new CryptoFrame(_sendCryptoOffset[i], _outgoingCrypto[i].GetRange(0, appCryptoChunk).ToArray()));
                    _sendCryptoOffset[i] += (ulong)appCryptoChunk;
                    _outgoingCrypto[i].RemoveRange(0, appCryptoChunk);
                }
            }

            // Höchstens ein Stream-Chunk (~MTU) pro Paket, begrenzt durch Flow Control und Sende-Budget.
            if (sendBudget > 0)
                AppendOneStreamChunk(frames, ref sendBudget);

            if (frames.Count == 0)
                break;

            ulong pn = Spaces[i].NextPacketNumber();
            // Erstes ECHTES 1-RTT-Paket – dessen Bestätigung darf den Handshake bestätigen (RFC 9001 §4.1.2).
            // WICHTIG: nur hier setzen, NIE in BuildZeroRttPackets. 0-RTT teilt sich zwar den Application-PN-Space
            // mit 1-RTT, aber §4.1.2 verlangt ausdrücklich die Quittung eines „1-RTT packet". Würde ein 0-RTT-Paket
            // diese PN belegen, bestätigte (bei akzeptiertem 0-RTT) dessen ACK den Handshake zu früh bzw. (bei
            // 0-RTT-Ablehnung) ein verirrter 0-RTT-ACK fälschlich. Da 0-RTT-PNs stets kleiner sind als die des
            // ersten 1-RTT-Pakets, impliziert LargestAck ≥ dieser PN nachweislich die Quittung eines echten 1-RTT-
            // Pakets – der Handshake-Key-Discard nach 0-RTT-Ablehnung bleibt damit korrekt.
            _firstOneRttPacketNumber ??= pn;
            int pnLength = PacketNumber.EncodeLength(pn, Spaces[i].LargestAckedByPeer);
            byte[] packet = ShortHeader.Build(keys, Dcid, pn, pnLength, FrameParser.Serialize(frames), keyPhase: _sendKeyPhase);
            RecordSent(i, pn, packet.Length, frames);
            datagrams.Add(packet);
            firstPacket = false;

            // Weiter nur, solange Budget übrig ist UND noch Stream-Daten anstehen.
            if (sendBudget <= 0 || !StreamMap.Values.Any(s => s.Send.HasPending))
                break;
        }
    }

    /// <summary>
    /// Hängt einen einzelnen Stream-Datenchunk an (ein Frame), sofern Flow Control/Budget es erlauben.
    /// </summary>
    private void AppendOneStreamChunk(List<Frame> frames, ref long sendBudget)
    {
        foreach (QuicStream stream in StreamMap.Values)
        {
            if (!stream.Send.HasPending)
                continue;
            ulong connWindow = _connSendLimit > _connSendUsed ? _connSendLimit - _connSendUsed : 0;
            if (connWindow == 0)
                return; // Verbindungsfenster erschöpft
            int chunk = (int)Math.Min(Math.Min((ulong)MaxStreamDataPerPacket, connWindow), (ulong)sendBudget);
            if (chunk <= 0)
                return;
            StreamFrame? sf = stream.Send.NextFrame(chunk);
            if (sf is null)
                continue;
            frames.Add(sf);
            _connSendUsed += (ulong)sf.Data.Length;
            sendBudget -= sf.Data.Length;
            return; // ein Chunk pro Paket
        }
    }

    /// <summary>
    /// Emittiert 0-RTT-Pakete (RFC 9001 §4) mit früh gequeueten Anwendungsdaten (typischerweise der HTTP/3-
    /// Anfrage), solange die 1-RTT-Schlüssel noch fehlen. Nur der Client sendet 0-RTT; die Pakete tragen
    /// Stream-Frames im Application-Packet-Number-Space und werden mit den 0-RTT-Schlüsseln geschützt
    /// (Long Header 0x01). Nach dem Handshake läuft der Rest über 1-RTT (gemeinsamer Stream-/PN-Zustand).
    /// </summary>
    private void BuildZeroRttPackets(List<byte[]> datagrams)
    {
        if (IsServer || _appKeysInstalled || _zeroRttKeys is not { } keys)
            return;
        int i = (int)EncryptionLevel.Application;

        // Grober Deckel am konservativen Initial-Congestion-Window; ein kleiner GET passt locker hinein.
        for (int packetCount = 0; packetCount < 10; packetCount++)
        {
            var frames = new List<Frame>();
            foreach (QuicStream stream in StreamMap.Values)
            {
                if (!stream.Send.HasPending)
                    continue;
                ulong connWindow = _connSendLimit > _connSendUsed ? _connSendLimit - _connSendUsed : 0;
                if (connWindow == 0)
                    break;
                int chunk = (int)Math.Min((ulong)MaxStreamDataPerPacket, connWindow);
                StreamFrame? sf = stream.Send.NextFrame(chunk);
                if (sf is null)
                    continue;
                frames.Add(sf);
                _connSendUsed += (ulong)sf.Data.Length;
                break; // ein Stream-Chunk pro Paket
            }
            if (frames.Count == 0)
                return;

            ulong pn = Spaces[i].NextPacketNumber();
            int pnLength = PacketNumber.EncodeLength(pn, Spaces[i].LargestAckedByPeer);
            byte[] packet = LongHeader.Build(keys, LongPacketType.ZeroRtt, Version, Dcid, Scid, default,
                pn, pnLength, FrameParser.Serialize(frames));
            RecordSent(i, pn, packet.Length, frames);
            datagrams.Add(packet);
            _zeroRttDataSent = true;
            _zeroRttMaxPacketNumber = pn; // PNs sind monoton ⇒ das ist die Grenze zu späteren 1-RTT-Paketen
        }
    }

    /// <summary>
    /// Behandelt eine 0-RTT-Ablehnung (RFC 9001 §4.6.2): Hat der Client Early Data gesendet, der Server sie
    /// aber nicht akzeptiert (kein early_data in EncryptedExtensions), werden die als 0-RTT gesendeten Frames
    /// sofort über 1-RTT wiederholt – ohne auf Zeitschwelle/PTO zu warten.
    /// </summary>
    private void MaybeHandleZeroRttRejection()
    {
        if (_zeroRttRejectionHandled || IsServer || !_zeroRttDataSent || !_appKeysInstalled)
            return;
        _zeroRttRejectionHandled = true;
        if (TlsHandshake?.EarlyDataAccepted == true)
            return; // akzeptiert – die Daten laufen normal weiter

        int i = (int)EncryptionLevel.Application;
        _retransmitQueue[i].AddRange(_recovery.OnZeroRttRejected(i, _zeroRttMaxPacketNumber));
    }

    private void DrainRetransmitQueue(int level, List<Frame> frames)
    {
        if (_retransmitQueue[level].Count == 0)
            return;
        frames.AddRange(_retransmitQueue[level]);
        _retransmitQueue[level].Clear();
    }

    private void RecordSent(int level, ulong packetNumber, int size, List<Frame> frames)
    {
        bool ackEliciting = frames.Any(f => f is not AckFrame and not PaddingFrame);
        if (!ackEliciting)
            return; // reine ACK-Pakete zählen weder zu bytes_in_flight noch zum Pacing-Budget
        _pacer.OnBytesSent(size);
        _idle.OnAckElicitingPacketSent(_clock.Elapsed.Ticks); // RFC 9000 §10.1
        List<Frame> retransmittable = frames.Where(f => f is CryptoFrame or StreamFrame).ToList();
        _recovery.OnPacketSent(level, new SentPacket
        {
            PacketNumber = packetNumber,
            TimeSentTicks = _clock.Elapsed.Ticks,
            AckEliciting = true,
            Size = size,
            RetransmittableFrames = retransmittable,
        });
    }

    /// <summary>
    /// Prüft die PTO (RFC 9002 §6.2) und reiht bei Ablauf Retransmissions ein. Periodisch aufrufen.
    /// </summary>
    public void CheckLossDetectionTimeout()
    {
        MaybeDiscardServerZeroRttKeys(); // rein zeitgesteuert (§4.9.3) – auch ohne weiteren Verkehr

        long deadline = _recovery.GetProbeTimeoutDeadline();
        if (deadline < 0 || _clock.Elapsed.Ticks < deadline)
            return;
        _recovery.OnProbeTimeoutFired();
        for (int level = 0; level < LevelCount; level++)
            if (WriteKeys[level] is not null)
                _retransmitQueue[level].AddRange(_recovery.GetProbeFrames(level));
    }

    private void CollectFlowControlFrames(List<Frame> frames)
    {
        foreach ((ulong id, QuicStream stream) in StreamMap)
        {
            ulong window = ReceiveWindowFor(stream.Id);
            if (window == 0 || stream.Receive.HighestReceivedOffset == 0)
                continue;
            StreamReceiveBuffer recv = stream.Receive;
            if (recv.MaxData - recv.BytesConsumed < window / 2)
            {
                recv.MaxData = recv.BytesConsumed + window;
                frames.Add(new MaxStreamDataFrame(id, recv.MaxData));
            }
        }

        ulong connWindow = LocalParams.InitialMaxDataValue;
        if (connWindow == 0)
            return;
        ulong totalConsumed = 0;
        foreach (QuicStream s in StreamMap.Values)
            totalConsumed += s.Receive.BytesConsumed;
        if (_localConnMaxData - totalConsumed < connWindow / 2)
        {
            _localConnMaxData = totalConsumed + connWindow;
            frames.Add(new MaxDataFrame(_localConnMaxData));
        }
    }

    // ---- Empfangen -------------------------------------------------------------------------

    /// <summary>
    /// Verarbeitet ein empfangenes UDP-Datagramm (mehrere Coalesced Packets möglich).
    /// </summary>
    /// <param name="ecn">
    /// Der ECN-Codepoint des empfangenen IP-Datagramms (RFC 9000 §13.4). Kann die Transportschicht ihn nicht
    /// aus dem IP-Header lesen (Standard bei BCL-UDP-Sockets), bleibt es bei Not-ECT; die Protokoll-Logik
    /// (Zählen, Melden im ACK, CE-Reaktion) funktioniert unabhängig davon und ist so voll testbar.
    /// </param>
    public void ProcessDatagram(ReadOnlySpan<byte> datagram, EcnCodepoint ecn = EcnCodepoint.NotEct)
    {
        MaybeTransitionToClosed();
        if (_idleTimedOut || datagram.IsEmpty || _state is ConnectionState.Draining or ConnectionState.Closed)
            return; // still geschlossen, entleerend oder leer

        // Anti-Amplification (RFC 9000 §8.1): empfangene Bytes zählen das Sendebudget hoch (bis zur Validierung).
        if (!_addressValidated)
            _amplificationReceived += datagram.Length;

        // Im Closing-Zustand keine Frames mehr verarbeiten; jedes eingehende Paket löst ein erneutes
        // CONNECTION_CLOSE aus (RFC 9000 §10.2.1, grob 1:1-ratenbegrenzt).
        if (_state == ConnectionState.Closing)
        {
            _closePacketPending = true;
            return;
        }

        // Sonderfälle vorab am ersten (nicht koaleszierbaren) Paket erkennen: Version Negotiation (Version 0),
        // Retry (eigener Typ, keine Länge) und nicht unterstützte Versionen (RFC 9000 §6, §17.2.1, §17.2.5).
        byte firstByte = datagram[0];
        if (PacketFormat.IsLongHeader(firstByte) && datagram.Length >= 5)
        {
            uint firstVersion = (uint)((datagram[1] << 24) | (datagram[2] << 16) | (datagram[3] << 8) | datagram[4]);
            if (firstVersion == 0)
            {
                HandleVersionNegotiationPacket(datagram);
                return;
            }
            if (PacketFormat.GetLongPacketType(firstByte) == LongPacketType.Retry)
            {
                HandleRetryPacket(datagram);
                return;
            }
            if (firstVersion != Version)
            {
                HandleUnsupportedVersion(datagram);
                return;
            }
        }

        int offset = 0;
        while (offset < datagram.Length)
        {
            byte first = datagram[offset];
            if (PacketFormat.IsShortHeader(first))
            {
                ProcessShortHeaderPacket(datagram[offset..], ecn);
                break;
            }

            if (offset + 5 > datagram.Length)
                break;
            uint version = (uint)((datagram[offset + 1] << 24) | (datagram[offset + 2] << 16) |
                                  (datagram[offset + 3] << 8) | datagram[offset + 4]);
            if (version == 0)
                break; // Version Negotiation nur als eigenständiges Datagramm (oben behandelt)

            LongPacketType type = PacketFormat.GetLongPacketType(first);
            if (!LongHeader.TryParse(datagram[offset..], out LongHeaderPrefix? prefix) || prefix is null)
                break;

            OnLongHeaderPacket(type, prefix);

            // 0-RTT (RFC 9001 §4): der Server entschlüsselt Early Data mit den 0-RTT-Read-Keys im
            // Application-Packet-Number-Space (Frames landen wie 1-RTT-Daten in der Application-Schicht).
            if (type == LongPacketType.ZeroRtt && IsServer && _zeroRttKeys is { } earlyKeys)
            {
                byte[] earlyPacket = datagram.Slice(offset, prefix.PacketEndOffset).ToArray();
                DecryptAndHandle(earlyKeys, EncryptionLevel.Application, earlyPacket, prefix.PacketNumberOffset, longHeader: true, ecn);
            }

            EncryptionLevel? level = type switch
            {
                LongPacketType.Initial => EncryptionLevel.Initial,
                LongPacketType.Handshake => EncryptionLevel.Handshake,
                _ => null,
            };
            if (level is { } lvl && ReadKeys[(int)lvl] is { } keys)
            {
                byte[] packet = datagram.Slice(offset, prefix.PacketEndOffset).ToArray();
                DecryptAndHandle(keys, lvl, packet, prefix.PacketNumberOffset, longHeader: true, ecn);
            }

            offset += prefix.PacketEndOffset;
        }

        // Nach dem Verarbeiten des Datagramms nicht mehr benötigte Schlüssel verwerfen (RFC 9001 §4.9):
        // Initial, sobald der Server ein Handshake-Paket verarbeitet hat; Handshake, sobald der Handshake bestätigt ist.
        MaybeDiscardInitialKeys();
        MaybeDiscardHandshakeKeys();
        MaybeDiscardServerZeroRttKeys(); // 0-RTT-Read-Keys nach Ablauf der 3×PTO-Frist (§4.9.3)
    }

    private void ProcessShortHeaderPacket(ReadOnlySpan<byte> packetSpan, EcnCodepoint ecn)
    {
        int i = (int)EncryptionLevel.Application;
        if (ReadKeys[i] is not { } current)
            return;
        if (!ShortHeader.TryLocatePacketNumber(packetSpan, Scid.Length, out ConnectionId dcid, out int pnOffset))
            return;
        // Nur Pakete an eine unserer aktiven (ausgegebenen) Connection IDs annehmen (RFC 9000 §5.1);
        // eine unbekannte DCID könnte ein Stateless Reset sein (§10.3).
        if (!_cids.IsLocalConnectionId(dcid))
        {
            TryHandleStatelessReset(packetSpan);
            return;
        }

        byte[] packet = packetSpan.ToArray();
        // Header Protection entfernen (HP-Key ist über Key Updates konstant) → dann das Key-Phase-Bit lesen.
        if (!current.RemoveHeaderProtection(packet, pnOffset, Spaces[i].LargestReceived, longHeader: false, out ulong pn, out int headerLength))
            return;

        bool packetKeyPhase = (packet[0] & 0x04) != 0;
        ReadOnlySpan<byte> header = packet.AsSpan(0, headerLength);
        ReadOnlySpan<byte> body = packet.AsSpan(headerLength);
        byte[] plaintext = new byte[packet.Length];
        int len;

        if (packetKeyPhase == _recvKeyPhase)
        {
            // Aktuelle Phase; bei Fehlschlag ggf. ein umsortiertes Paket der vorigen Phase (nach Update).
            if (current.Decrypt(pn, header, body, plaintext, out len)) { }
            else if (_prevAppReadKeys is { } prev && prev.Decrypt(pn, header, body, plaintext, out len)) { }
            else { TryHandleStatelessReset(packetSpan); return; }
        }
        else
        {
            // Kippendes Key-Phase-Bit ⇒ Key Update des Peers (RFC 9001 §6). Mit den nächsten Read-Keys prüfen.
            if (_nextAppReadKeys is not { } next || !next.Decrypt(pn, header, body, plaintext, out len))
            {
                TryHandleStatelessReset(packetSpan);
                return;
            }
            CommitPeerKeyUpdate(packetKeyPhase);
        }

        DeliverApplicationFrames(pn, plaintext, len, ecn);
    }

    /// <summary>
    /// Prüft, ob ein nicht verarbeitbares (Short-Header-)Datagramm ein Stateless Reset ist (RFC 9000 §10.3.1):
    /// enden die letzten 16 Bytes auf einen uns bekannten Stateless-Reset-Token des Peers, wird die Verbindung
    /// sofort in den Draining-Zustand versetzt.
    /// </summary>
    private bool TryHandleStatelessReset(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < StatelessReset.MinLength ||
            !_cids.MatchesRemoteStatelessResetToken(datagram[^StatelessReset.TokenLength..]))
            return false;
        StatelessResetReceived = true;
        EnterDraining();
        return true;
    }

    private void DeliverApplicationFrames(ulong packetNumber, byte[] plaintext, int length, EcnCodepoint ecn)
    {
        _idle.OnPacketReceived(_clock.Elapsed.Ticks); // RFC 9000 §10.1
        _anyPacketProcessed = true;
        Spaces[(int)EncryptionLevel.Application].RecordReceived(packetNumber, ecn);

        // Nur echte 1-RTT-Pakete (Short Header) landen hier – 0-RTT (Long Header 0x01) läuft über DecryptAndHandle.
        // Mit dem ersten 1-RTT-Paket kennt der Server die Obergrenze der 0-RTT-PNs und startet die kurze
        // Aufbewahrungsfrist seiner 0-RTT-Read-Keys (RFC 9001 §4.9.3): danach MUST er sie „within a short time"
        // verwerfen, RECOMMENDED 3×PTO. Sind bereits ALLE 0-RTT-Pakete da (lückenlos), verwirft er sofort.
        if (IsServer)
        {
            _serverOneRttPacketReceived = true;
            if (_zeroRttKeys is not null && _serverZeroRttDiscardDeadlineTicks < 0)
                _serverZeroRttDiscardDeadlineTicks = _clock.Elapsed.Ticks + ServerZeroRttDiscardDelay().Ticks;
            MaybeDiscardServerZeroRttKeysIfComplete();
        }

        DeliverFrames(EncryptionLevel.Application, plaintext.AsSpan(0, length));
    }

    private void DecryptAndHandle(PacketProtection keys, EncryptionLevel level, byte[] packet, int pnOffset, bool longHeader, EcnCodepoint ecn)
    {
        int i = (int)level;
        byte[] plaintext = new byte[packet.Length];
        if (!keys.UnprotectPacket(packet, pnOffset, Spaces[i].LargestReceived, longHeader, plaintext, out ulong pn, out int len))
            return;

        _idle.OnPacketReceived(_clock.Elapsed.Ticks); // RFC 9000 §10.1: Timer bei erfolgreichem Empfang neu starten
        _anyPacketProcessed = true;
        // Ein entschlüsseltes Handshake-Paket beweist, dass der Peer unsere Handshake-Schlüssel erhielt ⇒
        // die Adresse ist validiert (RFC 9000 §8.1), das Anti-Amplification-Limit entfällt.
        if (level == EncryptionLevel.Handshake)
        {
            _addressValidated = true;
            _handshakePacketReceived = true; // Server: löst später das Verwerfen der Initial-Keys aus (RFC 9001 §4.9.1)
        }
        Spaces[i].RecordReceived(pn, ecn);
        // Server-0-RTT-Empfang (Application-Level, Long Header): kommt ein reordertes 0-RTT-Paket erst NACH dem
        // ersten 1-RTT-Paket an und schließt es die letzte PN-Lücke, sind alle 0-RTT-Pakete da ⇒ Keys weg (§4.9.3).
        if (level == EncryptionLevel.Application)
            MaybeDiscardServerZeroRttKeysIfComplete();
        DeliverFrames(level, plaintext.AsSpan(0, len));
    }

    /// <summary>
    /// Parst die Frames eines Pakets; ein Kodier-/Unbekannt-Fehler ist FRAME_ENCODING_ERROR (RFC 9000 §12.4).
    /// </summary>
    private void DeliverFrames(EncryptionLevel level, ReadOnlySpan<byte> plaintext)
    {
        if (FrameParser.TryParseAll(plaintext, out List<Frame> frames) != FrameParseResult.Ok)
        {
            CloseWithTransportError(TransportError.FrameEncodingError, "malformed or unknown frame");
            return;
        }
        HandleFrames(level, frames);
    }

    /// <summary>
    /// Schließt die Verbindung wegen eines Protokollverstoßes der Gegenseite (RFC 9000 §11).
    /// </summary>
    private void CloseWithTransportError(TransportError error, string reason) => Close(error, reason);

    private void HandleFrames(EncryptionLevel level, List<Frame> frames)
    {
        foreach (Frame frame in frames)
        {
            if (_state != ConnectionState.Active)
                return; // eine Verletzung (Close) oder ein empfangenes CONNECTION_CLOSE beendete die Verbindung

            switch (frame)
            {
                case CryptoFrame crypto:
                    _recvCrypto[(int)level].Add(crypto.Offset, crypto.Data.Span);
                    DeliverCryptoToTls(level);
                    break;
                case AckFrame ack:
                    Spaces[(int)level].OnAckReceived(ack.LargestAcknowledged);
                    var ackDelay = TimeSpan.FromMicroseconds(ack.AckDelay * 8);
                    _retransmitQueue[(int)level].AddRange(
                        _recovery.OnAckReceived((int)level, ack, ackDelay, _clock.Elapsed.Ticks));
                    // Wird eines unserer 1-RTT-Pakete bestätigt, DARF der Client den Handshake als bestätigt ansehen
                    // (RFC 9001 §4.1.2) – auch ohne (ggf. verlorenes) HANDSHAKE_DONE.
                    if (level == EncryptionLevel.Application &&
                        _firstOneRttPacketNumber is { } firstPn && ack.LargestAcknowledged >= firstPn)
                        OnOneRttPacketAcknowledged();
                    break;
                case StreamFrame sf:
                    HandleStreamFrame(sf);
                    break;
                case MaxStreamDataFrame m when StreamMap.TryGetValue(m.StreamId, out QuicStream? s):
                    s.Send.MaxData = Math.Max(s.Send.MaxData, m.MaximumStreamData);
                    break;
                case MaxDataFrame md:
                    _connSendLimit = Math.Max(_connSendLimit, md.MaximumData);
                    break;
                case HandshakeDoneFrame:
                    OnHandshakeDoneReceived();
                    break;
                case NewConnectionIdFrame ncid:
                    HandleNewConnectionId(ncid);
                    break;
                case RetireConnectionIdFrame rcid:
                    _cids.RetireLocal(rcid.SequenceNumber); // Peer zieht eine unserer lokalen CIDs zurück
                    break;
                case PathChallengeFrame pc:
                    _pendingControlFrames.Add(new PathResponseFrame(pc.Data)); // RFC 9000 §8.2: zurückspiegeln
                    break;
                case PathResponseFrame pr:
                    if (_pathChallengePending == pr.Data) // passende Antwort → Pfad validiert
                    {
                        PathValidated = true;
                        _pathChallengePending = null;
                        _pathValidationDeadlineTicks = -1;
                    }
                    break;
                case ConnectionCloseFrame close:
                    PeerCloseFrame = close;
                    EnterDraining(); // RFC 9000 §10.2.2: bei Empfang eines CONNECTION_CLOSE entleeren
                    return;          // keine weiteren Frames dieses Pakets verarbeiten
            }

            if (level == EncryptionLevel.Application)
                OnApplicationFrameHandled(frame);
        }
    }

    private void EnterDraining()
    {
        if (_state is ConnectionState.Draining or ConnectionState.Closed)
            return;
        _state = ConnectionState.Draining;
        _closeDeadlineTicks = _clock.Elapsed.Ticks + CloseTimeout().Ticks;
    }

    private void HandleNewConnectionId(NewConnectionIdFrame frame)
    {
        List<RetireConnectionIdFrame> retires = _cids.OnNewConnectionId(frame, out bool dcidChanged, out ConnectionId newDcid);
        if (dcidChanged)
            Dcid = newDcid; // die bisherige DCID wurde durch „Retire Prior To" zurückgezogen
        foreach (RetireConnectionIdFrame retire in retires)
            _pendingControlFrames.Add(retire);
    }

    /// <summary>
    /// Baut ein Paket, das nur das CONNECTION_CLOSE trägt, auf dem höchsten verfügbaren Schutzniveau.
    /// </summary>
    private byte[]? BuildClosePacket()
    {
        if (_closeFrame is null)
            return null;
        byte[] payload = FrameParser.Serialize([_closeFrame]);

        int app = (int)EncryptionLevel.Application;
        if (WriteKeys[app] is { } appKeys)
        {
            ulong pn = Spaces[app].NextPacketNumber();
            return ShortHeader.Build(appKeys, Dcid, pn, PacketNumber.EncodeLength(pn, Spaces[app].LargestAckedByPeer), payload, keyPhase: _sendKeyPhase);
        }
        int hs = (int)EncryptionLevel.Handshake;
        if (WriteKeys[hs] is { } hsKeys)
        {
            ulong pn = Spaces[hs].NextPacketNumber();
            return LongHeader.Build(hsKeys, LongPacketType.Handshake, Version, Dcid, Scid, default, pn,
                PacketNumber.EncodeLength(pn, Spaces[hs].LargestAckedByPeer), payload);
        }
        int init = (int)EncryptionLevel.Initial;
        if (WriteKeys[init] is { } initKeys)
        {
            ulong pn = Spaces[init].NextPacketNumber();
            return InitialPacketFactory.BuildPadded(initKeys, Version, Dcid, Scid, InitialToken, pn,
                PacketNumber.EncodeLength(pn, Spaces[init].LargestAckedByPeer), payload);
        }
        return null;
    }

    private void HandleStreamFrame(StreamFrame sf)
    {
        var id = new StreamId(sf.StreamId);

        // STREAM_LIMIT_ERROR (RFC 9000 §4.6): ein vom Peer initiierter Stream jenseits des von uns gewährten Limits.
        if (!LocallyInitiated(id) && id.Index >= StreamLimitFor(id))
        {
            CloseWithTransportError(TransportError.StreamLimitError, "stream limit exceeded");
            return;
        }

        bool isNew = !StreamMap.ContainsKey(sf.StreamId);
        StreamReceiveResult result = GetOrCreateStream(id).Receive.Receive(sf.Offset, sf.Data.Span, sf.Fin);
        switch (result)
        {
            case StreamReceiveResult.FlowControlError:   // RFC 9000 §4.1
                CloseWithTransportError(TransportError.FlowControlError, "stream flow control exceeded");
                return;
            case StreamReceiveResult.FinalSizeError:     // RFC 9000 §4.5
                CloseWithTransportError(TransportError.FinalSizeError, "inconsistent final size");
                return;
        }

        OnStreamOpened(id, isNew);
    }

    /// <summary>
    /// Das von uns gewährte Stream-Limit (Anzahl) für die Kategorie von <paramref name="id"/>.
    /// </summary>
    private ulong StreamLimitFor(StreamId id)
        => id.IsUnidirectional ? LocalParams.InitialMaxStreamsUniValue : LocalParams.InitialMaxStreamsBidiValue;

    private void DeliverCryptoToTls(EncryptionLevel level)
    {
        if (TlsHandshake is null)
            return;
        int i = (int)level;
        byte[] contiguous = _recvCrypto[i].Contiguous();
        if (contiguous.Length <= _deliveredCrypto[i])
            return;

        TlsHandshake.ProvideCrypto(level, contiguous.AsSpan((int)_deliveredCrypto[i]));
        _deliveredCrypto[i] = contiguous.Length;

        MaybeInstallHandshakeKeys();
        MaybeInstallApplicationKeys();
        MaybeInstallZeroRttKeys();
        MaybeDecodePeerParameters();
    }

    /// <summary>
    /// Installiert die 0-RTT-Schlüssel aus dem <c>client_early_traffic_secret</c> (RFC 9001 §4), sobald es
    /// vorliegt: beim Client der Schreib-, beim Server der Leseschlüssel. Die 0-RTT-Suite steht (anders als die
    /// ausgehandelte) schon vor dem ServerHello fest, weil sie an das Ticket gebunden ist.
    /// </summary>
    private void MaybeInstallZeroRttKeys()
    {
        if (_zeroRttInstalled ||
            TlsHandshake?.EarlyTrafficSecret is not { } secret ||
            TlsHandshake.EarlyDataCipherSuite is not { } suite)
            return;
        var ks = new KeySchedule(suite);
        _zeroRttKeys = new PacketProtection(TrafficKeys.FromSecret(ks.Hash, secret, ks.AeadKeyLength), AeadFor(suite));
        _zeroRttInstalled = true;
    }

    // ---- Schlüsselinstallation -------------------------------------------------------------

    /// <summary>
    /// Installiert die Initial-Schlüssel aus <paramref name="dcid"/> in korrekter Richtung.
    /// </summary>
    protected void InstallInitialKeys(ConnectionId dcid)
    {
        InitialSecrets s = InitialSecrets.DeriveV1(dcid.Span);
        WriteKeys[(int)EncryptionLevel.Initial] = new PacketProtection(IsServer ? s.Server : s.Client);
        ReadKeys[(int)EncryptionLevel.Initial] = new PacketProtection(IsServer ? s.Client : s.Server);
    }

    /// <summary>
    /// <c>true</c>, sobald der TLS-Handshake bestätigt ist (Client: HANDSHAKE_DONE empfangen; Server: abgeschlossen).
    /// </summary>
    protected virtual bool HandshakeIsConfirmed => false;

    /// <summary>
    /// Verwirft die Schutzschlüssel eines Encryption-Levels (RFC 9001 §4.9): Schlüssel weg, ausstehende CRYPTO
    /// und Retransmits verworfen, der Loss-Recovery-Space aufgeräumt (RFC 9002 §6.4). Danach werden auf diesem
    /// Level weder Pakete gesendet (WriteKeys null) noch verarbeitet (ReadKeys null).
    /// </summary>
    private void DiscardKeys(EncryptionLevel level)
    {
        int i = (int)level;
        WriteKeys[i]?.Dispose();
        WriteKeys[i] = null;
        ReadKeys[i]?.Dispose();
        ReadKeys[i] = null;
        _outgoingCrypto[i].Clear();
        _retransmitQueue[i].Clear();
        _recovery.DiscardSpace(i);
    }

    /// <summary>
    /// Verwirft die Initial-Schlüssel (RFC 9001 §4.9.1): der Client, sobald er ein Handshake-Paket <b>gesendet</b>
    /// hat; der Server, sobald er ein Handshake-Paket <b>verarbeitet</b> hat. Genau diese Zeitpunkte schreibt die
    /// RFC vor – <b>nicht früher</b>: §4.9 verbietet das Verwerfen, solange die Gegenseite „nicht das Gleiche getan"
    /// hat, und man braucht die Initial-Keys noch, um den Initial der Gegenseite zu acken bzw. CRYPTO auf Initial-
    /// Level zu retransmittieren. Der Aufruf am Flight-/Datagramm-Ende sorgt dafür, dass die fälligen Initial-ACKs
    /// vorher raus sind. (Ein „früheres" Verwerfen wäre RFC-widrig und brächte nichts – ACK und Finished sind
    /// ohnehin im selben Flight.)
    /// </summary>
    private void MaybeDiscardInitialKeys()
    {
        if (_initialKeysDiscarded || WriteKeys[(int)EncryptionLevel.Initial] is null)
            return;
        if (!(IsServer ? _handshakePacketReceived : _handshakePacketSent))
            return;
        _initialKeysDiscarded = true;
        DiscardKeys(EncryptionLevel.Initial);
    }

    /// <summary>
    /// Verwirft die Handshake-Schlüssel, sobald der Handshake bestätigt ist (RFC 9001 §4.9.2) – ein
    /// bedingungsloses MUST, <b>ohne</b> Aufbewahrungsfenster. Geprüft und bewusst so: anders als §4.9.3 für
    /// 0-RTT (dort MAY „Servers … temporarily retain 0-RTT keys … three times the PTO" gegen Reordering)
    /// gewährt §4.9.2 <b>kein</b> Reordering-Fenster für Handshake-Keys. Das ist keine Auslassung, sondern
    /// Absicht: Bestätigung (§4.1.2) heißt beidseitig fertiger Handshake; laut §4.9 wird ab dann „new data …
    /// at the highest currently available encryption level" gesendet, auf tieferen Levels nur noch ACKs und
    /// CRYPTO-Retransmits. Ein spät reordertes Handshake-Paket trüge also höchstens schon bekannte CRYPTO-
    /// Daten oder ein Duplikat-ACK – nichts, dessen Verlust Inhalt kostet (bei 0-RTT erzeugt der Sender dagegen
    /// noch echte App-Daten, daher nur dort das Fenster). Schlüssel länger vorzuhalten verlängerte nur das
    /// Angriffsfenster – deshalb sofortiges Verwerfen. (Das „kurz für Reordering"-Behalten voriger Read-Keys
    /// betrifft ausschließlich das 1-RTT Key Update nach §6, nicht die Handshake-Keys.)
    /// </summary>
    private void MaybeDiscardHandshakeKeys()
    {
        if (_handshakeKeysDiscarded || !HandshakeIsConfirmed || WriteKeys[(int)EncryptionLevel.Handshake] is null)
            return;
        _handshakeKeysDiscarded = true;
        DiscardKeys(EncryptionLevel.Handshake);
    }

    /// <summary>
    /// Testhilfe: <c>true</c>, solange die Handshake-Schutzschlüssel installiert sind (RFC 9001 §4.9.2).
    /// </summary>
    internal bool HasHandshakeKeysForTest =>
        ReadKeys[(int)EncryptionLevel.Handshake] is not null || WriteKeys[(int)EncryptionLevel.Handshake] is not null;

    /// <summary>
    /// Testhilfe: <c>true</c>, solange die 0-RTT-Schlüssel installiert sind (RFC 9001 §4.9.3).
    /// </summary>
    internal bool HasZeroRttKeysForTest => _zeroRttKeys is not null;

    /// <summary>
    /// Testhilfe: überschreibt die 0-RTT-Verwerfungsfrist des Servers (statt 3×PTO), um sie deterministisch zu prüfen.
    /// </summary>
    internal TimeSpan? ServerZeroRttDiscardDelayForTest { get; set; }

    /// <summary>
    /// Aufbewahrungsfrist der Server-0-RTT-Read-Keys nach dem ersten 1-RTT-Paket (RFC 9001 §4.9.3: 3×PTO empfohlen).
    /// </summary>
    private TimeSpan ServerZeroRttDiscardDelay() =>
        ServerZeroRttDiscardDelayForTest ?? 3 * _recovery.Rtt.GetProbeTimeout(_recovery.MaxAckDelay);

    /// <summary>
    /// Verwirft die 0-RTT-Read-Keys des Servers, sobald die kurze Aufbewahrungsfrist nach dem ersten 1-RTT-Paket
    /// abgelaufen ist (RFC 9001 §4.9.3). Bis dahin bleiben sie installiert, um umsortierte 0-RTT-Pakete noch
    /// entschlüsseln zu können, ohne eine Neuübertragung über 1-RTT zu erzwingen.
    /// </summary>
    private void MaybeDiscardServerZeroRttKeys()
    {
        if (_zeroRttKeys is null || _serverZeroRttDiscardDeadlineTicks < 0 ||
            _clock.Elapsed.Ticks < _serverZeroRttDiscardDeadlineTicks)
            return;
        _zeroRttKeys.Dispose();
        _zeroRttKeys = null;
    }

    /// <summary>
    /// Verwirft die 0-RTT-Read-Keys des Servers <b>früher</b> als nach 3×PTO, sobald sicher alle 0-RTT-Pakete
    /// empfangen sind (RFC 9001 §4.9.3, letzter Satz: „A server MAY discard 0-RTT keys earlier if it determines
    /// that it has received all 0-RTT packets, … by keeping track of missing packet numbers"). 0-RTT-PNs beginnen
    /// bei 0 und liegen alle unter der ersten 1-RTT-PN; ist also bereits ein 1-RTT-Paket eingetroffen (Obergrenze
    /// bekannt) UND der Application-Space ab 0 lückenlos, kann kein reordertes 0-RTT-Paket mehr ausstehen.
    /// </summary>
    private void MaybeDiscardServerZeroRttKeysIfComplete()
    {
        if (!IsServer || _zeroRttKeys is null || !_serverOneRttPacketReceived ||
            !Spaces[(int)EncryptionLevel.Application].IsContiguousFromZero)
            return;
        _zeroRttKeys.Dispose();
        _zeroRttKeys = null;
    }

    private void MaybeInstallHandshakeKeys()
    {
        if (_handshakeKeysInstalled || TlsHandshake?.HandshakeSecrets is not { } hs || TlsHandshake.NegotiatedCipherSuite is not { } suite)
            return;
        var ks = new KeySchedule(suite);
        AeadAlgorithm aead = AeadFor(suite);
        byte[] write = IsServer ? hs.ServerHandshakeTrafficSecret : hs.ClientHandshakeTrafficSecret;
        byte[] read = IsServer ? hs.ClientHandshakeTrafficSecret : hs.ServerHandshakeTrafficSecret;
        WriteKeys[(int)EncryptionLevel.Handshake] = new PacketProtection(TrafficKeys.FromSecret(ks.Hash, write, ks.AeadKeyLength), aead);
        ReadKeys[(int)EncryptionLevel.Handshake] = new PacketProtection(TrafficKeys.FromSecret(ks.Hash, read, ks.AeadKeyLength), aead);
        _handshakeKeysInstalled = true;
    }

    /// <summary>
    /// AEAD-Verfahren zur Cipher Suite (Initial nutzt immer AES-128-GCM, RFC 9001 §5.2).
    /// </summary>
    private static AeadAlgorithm AeadFor(CipherSuite suite)
        => suite == CipherSuite.ChaCha20Poly1305Sha256 ? AeadAlgorithm.ChaCha20Poly1305 : AeadAlgorithm.AesGcm;

    private void MaybeInstallApplicationKeys()
    {
        if (_appKeysInstalled || TlsHandshake?.ApplicationSecrets is not { } app || TlsHandshake.NegotiatedCipherSuite is not { } suite)
            return;
        var ks = new KeySchedule(suite);
        byte[] write = IsServer ? app.ServerApplicationTrafficSecret : app.ClientApplicationTrafficSecret;
        byte[] read = IsServer ? app.ClientApplicationTrafficSecret : app.ServerApplicationTrafficSecret;

        _appHash = ks.Hash;
        _appHashLength = ks.HashLength;
        _appAead = AeadFor(suite);
        _appWriteTk = TrafficKeys.FromSecret(ks.Hash, write, ks.AeadKeyLength);
        _appReadTk = TrafficKeys.FromSecret(ks.Hash, read, ks.AeadKeyLength);
        WriteKeys[(int)EncryptionLevel.Application] = new PacketProtection(_appWriteTk, _appAead);
        ReadKeys[(int)EncryptionLevel.Application] = new PacketProtection(_appReadTk, _appAead);

        // Generation 1 der Read-Keys vorbereiten, um einen Key Update des Peers sofort dekodieren zu können.
        _nextAppReadTk = _appReadTk.Next(_appHash, _appHashLength);
        _nextAppReadKeys = new PacketProtection(_nextAppReadTk, _appAead);

        // Die im Handshake gelernte DCID ist die entfernte Connection ID mit Sequenz 0.
        _cids.InitializeRemote(Dcid);
        ApplyPeerStatelessResetToken();
        _appKeysInstalled = true;

        // RFC 9001 §4.9.3: Der Client SHOULD seine 0-RTT-Schlüssel verwerfen, sobald die 1-RTT-Schlüssel stehen –
        // „as they have no use after that moment": er sendet nach dem ersten 1-RTT-Paket keine 0-RTT-Pakete mehr
        // (§5.6) und empfängt selbst NIE welche (0-RTT ist client→server), hat also gar keinen 0-RTT-Read-Pfad.
        // Deshalb gibt es hier – anders als beim Server – bewusst KEIN Reordering-Fenster: reorderte/verspätete
        // Pakete am Client werden mit Initial-/Handshake-/1-RTT-Read-Keys entschützt, nie mit 0-RTT-Keys; und
        // verlorene 0-RTT-Daten werden über 1-RTT retransmittiert (Application-Retransmit-Queue ⇒ BuildApplication-
        // Packets), nicht neu als 0-RTT verschlüsselt. Sofort verwerfen minimiert das Angriffsfenster. (Nur der
        // SERVER behält 0-RTT-READ-Keys kurz für reorderte 0-RTT-Pakete – anderer Auslöser, §4.9.3, siehe unten.)
        if (!IsServer)
        {
            _zeroRttKeys?.Dispose();
            _zeroRttKeys = null;
        }
    }

    /// <summary>
    /// Übernimmt den <c>stateless_reset_token</c>-TP des Peers als Token der entfernten Handshake-CID.
    /// </summary>
    private void ApplyPeerStatelessResetToken()
    {
        if (PeerParams?.StatelessResetTokenValue is { } token)
            _cids.SetInitialRemoteToken(token);
    }

    // ---- Key Update (RFC 9001 §6) ----------------------------------------------------------

    /// <summary>
    /// Aktuelle Anzahl vollzogener 1-RTT-Key-Updates (Diagnose/Test).
    /// </summary>
    public uint KeyUpdateCount => _keyUpdateCount;

    /// <summary>
    /// Das aktuelle Key-Phase-Bit, das ausgehende 1-RTT-Pakete tragen.
    /// </summary>
    public bool CurrentKeyPhase => _sendKeyPhase;

    /// <summary>
    /// Leitet lokal einen 1-RTT-Key-Update ein (RFC 9001 §6.1): rotiert die eigenen Send-Keys auf die
    /// nächste Generation und kippt das Key-Phase-Bit. Die Read-Keys folgen, sobald der Peer mit der neuen
    /// Phase antwortet. Erfordert installierte Application-Keys.
    /// </summary>
    public bool InitiateKeyUpdate()
    {
        if (!_appKeysInstalled || _appWriteTk is null)
            return false;
        _appWriteTk = _appWriteTk.Next(_appHash, _appHashLength);
        WriteKeys[(int)EncryptionLevel.Application]?.Dispose();
        WriteKeys[(int)EncryptionLevel.Application] = new PacketProtection(_appWriteTk, _appAead);
        _sendKeyPhase = !_sendKeyPhase;
        _keyUpdateCount++;
        return true;
    }

    /// <summary>
    /// Vollzieht den durch ein gekipptes Key-Phase-Bit erkannten Key Update auf der Empfangsseite: die
    /// vorbereiteten nächsten Read-Keys werden aktiv (die bisherigen kurz für Reordering behalten), die
    /// übernächste Generation wird vorbereitet, und – falls noch nicht geschehen – rotieren auch die
    /// Send-Keys mit (Antwort auf den Update des Peers).
    /// </summary>
    private void CommitPeerKeyUpdate(bool newPhase)
    {
        int i = (int)EncryptionLevel.Application;
        _prevAppReadKeys?.Dispose();
        _prevAppReadKeys = ReadKeys[i];
        ReadKeys[i] = _nextAppReadKeys!;
        _appReadTk = _nextAppReadTk!;
        _recvKeyPhase = newPhase;

        _nextAppReadTk = _appReadTk.Next(_appHash, _appHashLength);
        _nextAppReadKeys = new PacketProtection(_nextAppReadTk, _appAead);

        if (_sendKeyPhase != newPhase)
        {
            _appWriteTk = _appWriteTk!.Next(_appHash, _appHashLength);
            WriteKeys[i]?.Dispose();
            WriteKeys[i] = new PacketProtection(_appWriteTk, _appAead);
            _sendKeyPhase = newPhase;
        }
        _keyUpdateCount++;
    }

    private void MaybeDecodePeerParameters()
    {
        if (PeerParams is not null || TlsHandshake?.PeerQuicTransportParameters is not { } bytes)
            return;
        if (TransportParameters.TryDecode(bytes, out TransportParameters? p) && p is not null)
        {
            PeerParams = p;
            _connSendLimit = p.InitialMaxDataValue;
            _idle.Negotiate(LocalParams.MaxIdleTimeoutMs, p.MaxIdleTimeoutMs); // effektiver Idle-Timeout (RFC 9000 §10.1)
            ApplyPeerStatelessResetToken();
            foreach (QuicStream s in StreamMap.Values)
                if (s.Send.MaxData == 0)
                    s.Send.MaxData = PeerSendLimitFor(s.Id);
        }
    }

    public virtual void Dispose()
    {
        TlsHandshake?.Dispose();
        foreach (PacketProtection? k in WriteKeys)
            k?.Dispose();
        foreach (PacketProtection? k in ReadKeys)
            k?.Dispose();
        _nextAppReadKeys?.Dispose();
        _prevAppReadKeys?.Dispose();
        // Auch die 0-RTT-Keys freigeben: Endet die Verbindung, bevor sie regulär verworfen wurden (Server vor
        // Ablauf der 3×PTO-Frist bzw. vor lückenlosem Empfang, RFC 9001 §4.9.3), lägen sie sonst bis zum GC
        // undisposed vor. Nullen hält den Zustand konsistent zu den anderen Discard-Pfaden (idempotent).
        _zeroRttKeys?.Dispose();
        _zeroRttKeys = null;
        GC.SuppressFinalize(this);
    }
}
