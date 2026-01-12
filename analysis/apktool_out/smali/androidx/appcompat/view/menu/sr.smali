.class public Landroidx/appcompat/view/menu/sr;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/sr$b;,
        Landroidx/appcompat/view/menu/sr$c;,
        Landroidx/appcompat/view/menu/sr$a;
    }
.end annotation


# static fields
.field public static final k:Ljava/lang/Object;

.field public static final l:Ljava/util/Map;


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Ljava/lang/String;

.field public final c:Landroidx/appcompat/view/menu/ss;

.field public final d:Landroidx/appcompat/view/menu/qe;

.field public final e:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public final f:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public final g:Landroidx/appcompat/view/menu/g80;

.field public final h:Landroidx/appcompat/view/menu/al0;

.field public final i:Ljava/util/List;

.field public final j:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/sr;->k:Ljava/lang/Object;

    new-instance v0, Landroidx/appcompat/view/menu/n4;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/n4;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/sr;->l:Ljava/util/Map;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Landroidx/appcompat/view/menu/ss;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/sr;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/sr;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/sr;->i:Ljava/util/List;

    new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/sr;->j:Ljava/util/List;

    invoke-static {p1}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/content/Context;

    iput-object v0, p0, Landroidx/appcompat/view/menu/sr;->a:Landroid/content/Context;

    invoke-static {p2}, Landroidx/appcompat/view/menu/ij0;->e(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    iput-object p2, p0, Landroidx/appcompat/view/menu/sr;->b:Ljava/lang/String;

    invoke-static {p3}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Landroidx/appcompat/view/menu/ss;

    iput-object p2, p0, Landroidx/appcompat/view/menu/sr;->c:Landroidx/appcompat/view/menu/ss;

    invoke-static {}, Lcom/google/firebase/provider/FirebaseInitProvider;->b()Landroidx/appcompat/view/menu/pw0;

    move-result-object p2

    const-string v0, "Firebase"

    invoke-static {v0}, Landroidx/appcompat/view/menu/ts;->b(Ljava/lang/String;)V

    const-string v0, "ComponentDiscovery"

    invoke-static {v0}, Landroidx/appcompat/view/menu/ts;->b(Ljava/lang/String;)V

    const-class v0, Lcom/google/firebase/components/ComponentDiscoveryService;

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/be;->c(Landroid/content/Context;Ljava/lang/Class;)Landroidx/appcompat/view/menu/be;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/be;->b()Ljava/util/List;

    move-result-object v0

    invoke-static {}, Landroidx/appcompat/view/menu/ts;->a()V

    const-string v2, "Runtime"

    invoke-static {v2}, Landroidx/appcompat/view/menu/ts;->b(Ljava/lang/String;)V

    sget-object v2, Landroidx/appcompat/view/menu/a31;->m:Landroidx/appcompat/view/menu/a31;

    invoke-static {v2}, Landroidx/appcompat/view/menu/qe;->k(Ljava/util/concurrent/Executor;)Landroidx/appcompat/view/menu/qe$b;

    move-result-object v2

    invoke-virtual {v2, v0}, Landroidx/appcompat/view/menu/qe$b;->d(Ljava/util/Collection;)Landroidx/appcompat/view/menu/qe$b;

    move-result-object v0

    new-instance v2, Lcom/google/firebase/FirebaseCommonRegistrar;

    invoke-direct {v2}, Lcom/google/firebase/FirebaseCommonRegistrar;-><init>()V

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/qe$b;->c(Lcom/google/firebase/components/ComponentRegistrar;)Landroidx/appcompat/view/menu/qe$b;

    move-result-object v0

    new-instance v2, Lcom/google/firebase/concurrent/ExecutorsRegistrar;

    invoke-direct {v2}, Lcom/google/firebase/concurrent/ExecutorsRegistrar;-><init>()V

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/qe$b;->c(Lcom/google/firebase/components/ComponentRegistrar;)Landroidx/appcompat/view/menu/qe$b;

    move-result-object v0

    const-class v2, Landroid/content/Context;

    new-array v3, v1, [Ljava/lang/Class;

    invoke-static {p1, v2, v3}, Landroidx/appcompat/view/menu/td;->s(Ljava/lang/Object;Ljava/lang/Class;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/td;

    move-result-object v2

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/qe$b;->b(Landroidx/appcompat/view/menu/td;)Landroidx/appcompat/view/menu/qe$b;

    move-result-object v0

    const-class v2, Landroidx/appcompat/view/menu/sr;

    new-array v3, v1, [Ljava/lang/Class;

    invoke-static {p0, v2, v3}, Landroidx/appcompat/view/menu/td;->s(Ljava/lang/Object;Ljava/lang/Class;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/td;

    move-result-object v2

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/qe$b;->b(Landroidx/appcompat/view/menu/td;)Landroidx/appcompat/view/menu/qe$b;

    move-result-object v0

    const-class v2, Landroidx/appcompat/view/menu/ss;

    new-array v3, v1, [Ljava/lang/Class;

    invoke-static {p3, v2, v3}, Landroidx/appcompat/view/menu/td;->s(Ljava/lang/Object;Ljava/lang/Class;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/td;

    move-result-object p3

    invoke-virtual {v0, p3}, Landroidx/appcompat/view/menu/qe$b;->b(Landroidx/appcompat/view/menu/td;)Landroidx/appcompat/view/menu/qe$b;

    move-result-object p3

    new-instance v0, Landroidx/appcompat/view/menu/fe;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/fe;-><init>()V

    invoke-virtual {p3, v0}, Landroidx/appcompat/view/menu/qe$b;->g(Landroidx/appcompat/view/menu/he;)Landroidx/appcompat/view/menu/qe$b;

    move-result-object p3

    invoke-static {p1}, Landroidx/appcompat/view/menu/k41;->a(Landroid/content/Context;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {}, Lcom/google/firebase/provider/FirebaseInitProvider;->c()Z

    move-result v0

    if-eqz v0, :cond_0

    const-class v0, Landroidx/appcompat/view/menu/pw0;

    new-array v1, v1, [Ljava/lang/Class;

    invoke-static {p2, v0, v1}, Landroidx/appcompat/view/menu/td;->s(Ljava/lang/Object;Ljava/lang/Class;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/td;

    move-result-object p2

    invoke-virtual {p3, p2}, Landroidx/appcompat/view/menu/qe$b;->b(Landroidx/appcompat/view/menu/td;)Landroidx/appcompat/view/menu/qe$b;

    :cond_0
    invoke-virtual {p3}, Landroidx/appcompat/view/menu/qe$b;->e()Landroidx/appcompat/view/menu/qe;

    move-result-object p2

    iput-object p2, p0, Landroidx/appcompat/view/menu/sr;->d:Landroidx/appcompat/view/menu/qe;

    invoke-static {}, Landroidx/appcompat/view/menu/ts;->a()V

    new-instance p3, Landroidx/appcompat/view/menu/g80;

    new-instance v0, Landroidx/appcompat/view/menu/qr;

    invoke-direct {v0, p0, p1}, Landroidx/appcompat/view/menu/qr;-><init>(Landroidx/appcompat/view/menu/sr;Landroid/content/Context;)V

    invoke-direct {p3, v0}, Landroidx/appcompat/view/menu/g80;-><init>(Landroidx/appcompat/view/menu/al0;)V

    iput-object p3, p0, Landroidx/appcompat/view/menu/sr;->g:Landroidx/appcompat/view/menu/g80;

    const-class p1, Landroidx/appcompat/view/menu/rj;

    invoke-interface {p2, p1}, Landroidx/appcompat/view/menu/wd;->d(Ljava/lang/Class;)Landroidx/appcompat/view/menu/al0;

    move-result-object p1

    iput-object p1, p0, Landroidx/appcompat/view/menu/sr;->h:Landroidx/appcompat/view/menu/al0;

    new-instance p1, Landroidx/appcompat/view/menu/rr;

    invoke-direct {p1, p0}, Landroidx/appcompat/view/menu/rr;-><init>(Landroidx/appcompat/view/menu/sr;)V

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/sr;->g(Landroidx/appcompat/view/menu/sr$a;)V

    invoke-static {}, Landroidx/appcompat/view/menu/ts;->a()V

    return-void
.end method

.method public static synthetic a(Landroidx/appcompat/view/menu/sr;Z)V
    .locals 0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/sr;->v(Z)V

    return-void
.end method

.method public static synthetic b(Landroidx/appcompat/view/menu/sr;Landroid/content/Context;)Landroidx/appcompat/view/menu/ui;
    .locals 0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/sr;->u(Landroid/content/Context;)Landroidx/appcompat/view/menu/ui;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic c()Ljava/lang/Object;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/sr;->k:Ljava/lang/Object;

    return-object v0
.end method

.method public static synthetic d(Landroidx/appcompat/view/menu/sr;)V
    .locals 0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->o()V

    return-void
.end method

.method public static synthetic e(Landroidx/appcompat/view/menu/sr;)Ljava/util/concurrent/atomic/AtomicBoolean;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/sr;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    return-object p0
.end method

.method public static synthetic f(Landroidx/appcompat/view/menu/sr;Z)V
    .locals 0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/sr;->x(Z)V

    return-void
.end method

.method public static k()Landroidx/appcompat/view/menu/sr;
    .locals 4

    sget-object v0, Landroidx/appcompat/view/menu/sr;->k:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Landroidx/appcompat/view/menu/sr;->l:Ljava/util/Map;

    const-string v2, "[DEFAULT]"

    invoke-interface {v1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/sr;

    if-eqz v1, :cond_0

    iget-object v2, v1, Landroidx/appcompat/view/menu/sr;->h:Landroidx/appcompat/view/menu/al0;

    invoke-interface {v2}, Landroidx/appcompat/view/menu/al0;->get()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/rj;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/rj;->l()Landroidx/appcompat/view/menu/vy0;

    monitor-exit v0

    return-object v1

    :catchall_0
    move-exception v1

    goto :goto_0

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Default FirebaseApp is not initialized in this process "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {}, Landroidx/appcompat/view/menu/zj0;->a()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, ". Make sure to call FirebaseApp.initializeApp(Context) first."

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v1
.end method

.method public static p(Landroid/content/Context;)Landroidx/appcompat/view/menu/sr;
    .locals 3

    sget-object v0, Landroidx/appcompat/view/menu/sr;->k:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Landroidx/appcompat/view/menu/sr;->l:Ljava/util/Map;

    const-string v2, "[DEFAULT]"

    invoke-interface {v1, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {}, Landroidx/appcompat/view/menu/sr;->k()Landroidx/appcompat/view/menu/sr;

    move-result-object p0

    monitor-exit v0

    return-object p0

    :catchall_0
    move-exception p0

    goto :goto_0

    :cond_0
    invoke-static {p0}, Landroidx/appcompat/view/menu/ss;->a(Landroid/content/Context;)Landroidx/appcompat/view/menu/ss;

    move-result-object v1

    if-nez v1, :cond_1

    monitor-exit v0

    const/4 p0, 0x0

    return-object p0

    :cond_1
    invoke-static {p0, v1}, Landroidx/appcompat/view/menu/sr;->q(Landroid/content/Context;Landroidx/appcompat/view/menu/ss;)Landroidx/appcompat/view/menu/sr;

    move-result-object p0

    monitor-exit v0

    return-object p0

    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public static q(Landroid/content/Context;Landroidx/appcompat/view/menu/ss;)Landroidx/appcompat/view/menu/sr;
    .locals 1

    const-string v0, "[DEFAULT]"

    invoke-static {p0, p1, v0}, Landroidx/appcompat/view/menu/sr;->r(Landroid/content/Context;Landroidx/appcompat/view/menu/ss;Ljava/lang/String;)Landroidx/appcompat/view/menu/sr;

    move-result-object p0

    return-object p0
.end method

.method public static r(Landroid/content/Context;Landroidx/appcompat/view/menu/ss;Ljava/lang/String;)Landroidx/appcompat/view/menu/sr;
    .locals 5

    invoke-static {p0}, Landroidx/appcompat/view/menu/sr$b;->b(Landroid/content/Context;)V

    invoke-static {p2}, Landroidx/appcompat/view/menu/sr;->w(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p0

    :goto_0
    sget-object v0, Landroidx/appcompat/view/menu/sr;->k:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Landroidx/appcompat/view/menu/sr;->l:Ljava/util/Map;

    invoke-interface {v1, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    xor-int/lit8 v2, v2, 0x1

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "FirebaseApp name "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, " already exists!"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-static {v2, v3}, Landroidx/appcompat/view/menu/ij0;->m(ZLjava/lang/Object;)V

    const-string v2, "Application context cannot be null."

    invoke-static {p0, v2}, Landroidx/appcompat/view/menu/ij0;->j(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v2, Landroidx/appcompat/view/menu/sr;

    invoke-direct {v2, p0, p2, p1}, Landroidx/appcompat/view/menu/sr;-><init>(Landroid/content/Context;Ljava/lang/String;Landroidx/appcompat/view/menu/ss;)V

    invoke-interface {v1, p2, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/sr;->o()V

    return-object v2

    :catchall_0
    move-exception p0

    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p0
.end method

.method public static w(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Landroidx/appcompat/view/menu/sr;

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->b:Ljava/lang/String;

    check-cast p1, Landroidx/appcompat/view/menu/sr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/sr;->l()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public g(Landroidx/appcompat/view/menu/sr$a;)V
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->h()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {}, Landroidx/appcompat/view/menu/u7;->b()Landroidx/appcompat/view/menu/u7;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/u7;->d()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    invoke-interface {p1, v0}, Landroidx/appcompat/view/menu/sr$a;->a(Z)V

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->i:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final h()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    const-string v1, "FirebaseApp was deleted"

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ij0;->m(ZLjava/lang/Object;)V

    return-void
.end method

.method public hashCode()I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->b:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v0

    return v0
.end method

.method public i(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->h()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->d:Landroidx/appcompat/view/menu/qe;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/wd;->a(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public j()Landroid/content/Context;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->h()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->a:Landroid/content/Context;

    return-object v0
.end method

.method public l()Ljava/lang/String;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->h()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->b:Ljava/lang/String;

    return-object v0
.end method

.method public m()Landroidx/appcompat/view/menu/ss;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->h()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->c:Landroidx/appcompat/view/menu/ss;

    return-object v0
.end method

.method public n()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->l()Ljava/lang/String;

    move-result-object v1

    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    invoke-static {v1}, Landroidx/appcompat/view/menu/w7;->a([B)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "+"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->m()Landroidx/appcompat/view/menu/ss;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/ss;->c()Ljava/lang/String;

    move-result-object v1

    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    invoke-static {v1}, Landroidx/appcompat/view/menu/w7;->a([B)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final o()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->a:Landroid/content/Context;

    invoke-static {v0}, Landroidx/appcompat/view/menu/k41;->a(Landroid/content/Context;)Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    if-eqz v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Device in Direct Boot Mode: postponing initialization of Firebase APIs for app "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->l()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->a:Landroid/content/Context;

    invoke-static {v0}, Landroidx/appcompat/view/menu/sr$c;->a(Landroid/content/Context;)V

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Device unlocked: initializing all Firebase APIs for app "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->l()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->d:Landroidx/appcompat/view/menu/qe;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->t()Z

    move-result v1

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/qe;->n(Z)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->h:Landroidx/appcompat/view/menu/al0;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/al0;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/rj;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/rj;->l()Landroidx/appcompat/view/menu/vy0;

    :goto_0
    return-void
.end method

.method public s()Z
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->h()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->g:Landroidx/appcompat/view/menu/g80;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/g80;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/ui;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ui;->b()Z

    move-result v0

    return v0
.end method

.method public t()Z
    .locals 2

    const-string v0, "[DEFAULT]"

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->l()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    invoke-static {p0}, Landroidx/appcompat/view/menu/sf0;->c(Ljava/lang/Object;)Landroidx/appcompat/view/menu/sf0$a;

    move-result-object v0

    const-string v1, "name"

    iget-object v2, p0, Landroidx/appcompat/view/menu/sr;->b:Ljava/lang/String;

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/sf0$a;->a(Ljava/lang/String;Ljava/lang/Object;)Landroidx/appcompat/view/menu/sf0$a;

    move-result-object v0

    const-string v1, "options"

    iget-object v2, p0, Landroidx/appcompat/view/menu/sr;->c:Landroidx/appcompat/view/menu/ss;

    invoke-virtual {v0, v1, v2}, Landroidx/appcompat/view/menu/sf0$a;->a(Ljava/lang/String;Ljava/lang/Object;)Landroidx/appcompat/view/menu/sf0$a;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/sf0$a;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final synthetic u(Landroid/content/Context;)Landroidx/appcompat/view/menu/ui;
    .locals 4

    new-instance v0, Landroidx/appcompat/view/menu/ui;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/sr;->n()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/sr;->d:Landroidx/appcompat/view/menu/qe;

    const-class v3, Landroidx/appcompat/view/menu/ol0;

    invoke-interface {v2, v3}, Landroidx/appcompat/view/menu/wd;->a(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/ol0;

    invoke-direct {v0, p1, v1, v2}, Landroidx/appcompat/view/menu/ui;-><init>(Landroid/content/Context;Ljava/lang/String;Landroidx/appcompat/view/menu/ol0;)V

    return-object v0
.end method

.method public final synthetic v(Z)V
    .locals 0

    if-nez p1, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/sr;->h:Landroidx/appcompat/view/menu/al0;

    invoke-interface {p1}, Landroidx/appcompat/view/menu/al0;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/rj;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/rj;->l()Landroidx/appcompat/view/menu/vy0;

    :cond_0
    return-void
.end method

.method public final x(Z)V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/sr;->i:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/sr$a;

    invoke-interface {v1, p1}, Landroidx/appcompat/view/menu/sr$a;->a(Z)V

    goto :goto_0

    :cond_0
    return-void
.end method
