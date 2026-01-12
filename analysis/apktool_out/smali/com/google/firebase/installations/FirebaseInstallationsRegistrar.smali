.class public Lcom/google/firebase/installations/FirebaseInstallationsRegistrar;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation


# static fields
.field private static final LIBRARY_NAME:Ljava/lang/String; = "fire-installations"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static synthetic a(Landroidx/appcompat/view/menu/wd;)Landroidx/appcompat/view/menu/fs;
    .locals 0

    invoke-static {p0}, Lcom/google/firebase/installations/FirebaseInstallationsRegistrar;->lambda$getComponents$0(Landroidx/appcompat/view/menu/wd;)Landroidx/appcompat/view/menu/fs;

    move-result-object p0

    return-object p0
.end method

.method private static synthetic lambda$getComponents$0(Landroidx/appcompat/view/menu/wd;)Landroidx/appcompat/view/menu/fs;
    .locals 6

    new-instance v0, Landroidx/appcompat/view/menu/es;

    const-class v1, Landroidx/appcompat/view/menu/sr;

    invoke-interface {p0, v1}, Landroidx/appcompat/view/menu/wd;->a(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/sr;

    const-class v2, Landroidx/appcompat/view/menu/az;

    invoke-interface {p0, v2}, Landroidx/appcompat/view/menu/wd;->d(Ljava/lang/Class;)Landroidx/appcompat/view/menu/al0;

    move-result-object v2

    const-class v3, Landroidx/appcompat/view/menu/t7;

    const-class v4, Ljava/util/concurrent/ExecutorService;

    invoke-static {v3, v4}, Landroidx/appcompat/view/menu/ql0;->a(Ljava/lang/Class;Ljava/lang/Class;)Landroidx/appcompat/view/menu/ql0;

    move-result-object v3

    invoke-interface {p0, v3}, Landroidx/appcompat/view/menu/wd;->e(Landroidx/appcompat/view/menu/ql0;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/concurrent/ExecutorService;

    const-class v4, Landroidx/appcompat/view/menu/j8;

    const-class v5, Ljava/util/concurrent/Executor;

    invoke-static {v4, v5}, Landroidx/appcompat/view/menu/ql0;->a(Ljava/lang/Class;Ljava/lang/Class;)Landroidx/appcompat/view/menu/ql0;

    move-result-object v4

    invoke-interface {p0, v4}, Landroidx/appcompat/view/menu/wd;->e(Landroidx/appcompat/view/menu/ql0;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/util/concurrent/Executor;

    invoke-static {p0}, Landroidx/appcompat/view/menu/yr;->a(Ljava/util/concurrent/Executor;)Ljava/util/concurrent/Executor;

    move-result-object p0

    invoke-direct {v0, v1, v2, v3, p0}, Landroidx/appcompat/view/menu/es;-><init>(Landroidx/appcompat/view/menu/sr;Landroidx/appcompat/view/menu/al0;Ljava/util/concurrent/ExecutorService;Ljava/util/concurrent/Executor;)V

    return-object v0
.end method


# virtual methods
.method public getComponents()Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Landroidx/appcompat/view/menu/td;",
            ">;"
        }
    .end annotation

    const-class v0, Landroidx/appcompat/view/menu/fs;

    invoke-static {v0}, Landroidx/appcompat/view/menu/td;->e(Ljava/lang/Class;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    const-string v1, "fire-installations"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/td$b;->h(Ljava/lang/String;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    const-class v2, Landroidx/appcompat/view/menu/sr;

    invoke-static {v2}, Landroidx/appcompat/view/menu/hl;->j(Ljava/lang/Class;)Landroidx/appcompat/view/menu/hl;

    move-result-object v2

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    const-class v2, Landroidx/appcompat/view/menu/az;

    invoke-static {v2}, Landroidx/appcompat/view/menu/hl;->h(Ljava/lang/Class;)Landroidx/appcompat/view/menu/hl;

    move-result-object v2

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    const-class v2, Landroidx/appcompat/view/menu/t7;

    const-class v3, Ljava/util/concurrent/ExecutorService;

    invoke-static {v2, v3}, Landroidx/appcompat/view/menu/ql0;->a(Ljava/lang/Class;Ljava/lang/Class;)Landroidx/appcompat/view/menu/ql0;

    move-result-object v2

    invoke-static {v2}, Landroidx/appcompat/view/menu/hl;->i(Landroidx/appcompat/view/menu/ql0;)Landroidx/appcompat/view/menu/hl;

    move-result-object v2

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    const-class v2, Landroidx/appcompat/view/menu/j8;

    const-class v3, Ljava/util/concurrent/Executor;

    invoke-static {v2, v3}, Landroidx/appcompat/view/menu/ql0;->a(Ljava/lang/Class;Ljava/lang/Class;)Landroidx/appcompat/view/menu/ql0;

    move-result-object v2

    invoke-static {v2}, Landroidx/appcompat/view/menu/hl;->i(Landroidx/appcompat/view/menu/ql0;)Landroidx/appcompat/view/menu/hl;

    move-result-object v2

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/td$b;->b(Landroidx/appcompat/view/menu/hl;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    new-instance v2, Landroidx/appcompat/view/menu/hs;

    invoke-direct {v2}, Landroidx/appcompat/view/menu/hs;-><init>()V

    invoke-virtual {v0, v2}, Landroidx/appcompat/view/menu/td$b;->f(Landroidx/appcompat/view/menu/ce;)Landroidx/appcompat/view/menu/td$b;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/td$b;->d()Landroidx/appcompat/view/menu/td;

    move-result-object v0

    invoke-static {}, Landroidx/appcompat/view/menu/zy;->a()Landroidx/appcompat/view/menu/td;

    move-result-object v2

    const-string v3, "17.2.0"

    invoke-static {v1, v3}, Landroidx/appcompat/view/menu/s80;->b(Ljava/lang/String;Ljava/lang/String;)Landroidx/appcompat/view/menu/td;

    move-result-object v1

    filled-new-array {v0, v2, v1}, [Landroidx/appcompat/view/menu/td;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method
