.class public final Landroidx/appcompat/view/menu/qe$b;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/qe;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation


# instance fields
.field public final a:Ljava/util/concurrent/Executor;

.field public final b:Ljava/util/List;

.field public final c:Ljava/util/List;

.field public d:Landroidx/appcompat/view/menu/he;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/Executor;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/qe$b;->b:Ljava/util/List;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/qe$b;->c:Ljava/util/List;

    sget-object v0, Landroidx/appcompat/view/menu/he;->a:Landroidx/appcompat/view/menu/he;

    iput-object v0, p0, Landroidx/appcompat/view/menu/qe$b;->d:Landroidx/appcompat/view/menu/he;

    iput-object p1, p0, Landroidx/appcompat/view/menu/qe$b;->a:Ljava/util/concurrent/Executor;

    return-void
.end method

.method public static synthetic a(Lcom/google/firebase/components/ComponentRegistrar;)Lcom/google/firebase/components/ComponentRegistrar;
    .locals 0

    invoke-static {p0}, Landroidx/appcompat/view/menu/qe$b;->f(Lcom/google/firebase/components/ComponentRegistrar;)Lcom/google/firebase/components/ComponentRegistrar;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic f(Lcom/google/firebase/components/ComponentRegistrar;)Lcom/google/firebase/components/ComponentRegistrar;
    .locals 0

    return-object p0
.end method


# virtual methods
.method public b(Landroidx/appcompat/view/menu/td;)Landroidx/appcompat/view/menu/qe$b;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/qe$b;->c:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-object p0
.end method

.method public c(Lcom/google/firebase/components/ComponentRegistrar;)Landroidx/appcompat/view/menu/qe$b;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/qe$b;->b:Ljava/util/List;

    new-instance v1, Landroidx/appcompat/view/menu/re;

    invoke-direct {v1, p1}, Landroidx/appcompat/view/menu/re;-><init>(Lcom/google/firebase/components/ComponentRegistrar;)V

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-object p0
.end method

.method public d(Ljava/util/Collection;)Landroidx/appcompat/view/menu/qe$b;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/qe$b;->b:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    return-object p0
.end method

.method public e()Landroidx/appcompat/view/menu/qe;
    .locals 7

    new-instance v6, Landroidx/appcompat/view/menu/qe;

    iget-object v1, p0, Landroidx/appcompat/view/menu/qe$b;->a:Ljava/util/concurrent/Executor;

    iget-object v2, p0, Landroidx/appcompat/view/menu/qe$b;->b:Ljava/util/List;

    iget-object v3, p0, Landroidx/appcompat/view/menu/qe$b;->c:Ljava/util/List;

    iget-object v4, p0, Landroidx/appcompat/view/menu/qe$b;->d:Landroidx/appcompat/view/menu/he;

    const/4 v5, 0x0

    move-object v0, v6

    invoke-direct/range {v0 .. v5}, Landroidx/appcompat/view/menu/qe;-><init>(Ljava/util/concurrent/Executor;Ljava/lang/Iterable;Ljava/util/Collection;Landroidx/appcompat/view/menu/he;Landroidx/appcompat/view/menu/qe$a;)V

    return-object v6
.end method

.method public g(Landroidx/appcompat/view/menu/he;)Landroidx/appcompat/view/menu/qe$b;
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/qe$b;->d:Landroidx/appcompat/view/menu/he;

    return-object p0
.end method
