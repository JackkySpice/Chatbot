.class public Landroidx/appcompat/view/menu/ia1;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final a:Ljava/util/concurrent/Executor;

.field public final b:Landroidx/appcompat/view/menu/fp;

.field public final c:Landroidx/appcompat/view/menu/la1;

.field public final d:Landroidx/appcompat/view/menu/ly0;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/fp;Landroidx/appcompat/view/menu/la1;Landroidx/appcompat/view/menu/ly0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ia1;->a:Ljava/util/concurrent/Executor;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ia1;->b:Landroidx/appcompat/view/menu/fp;

    iput-object p3, p0, Landroidx/appcompat/view/menu/ia1;->c:Landroidx/appcompat/view/menu/la1;

    iput-object p4, p0, Landroidx/appcompat/view/menu/ia1;->d:Landroidx/appcompat/view/menu/ly0;

    return-void
.end method

.method public static synthetic a(Landroidx/appcompat/view/menu/ia1;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ia1;->d()Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic b(Landroidx/appcompat/view/menu/ia1;)V
    .locals 0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ia1;->e()V

    return-void
.end method


# virtual methods
.method public c()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/ia1;->a:Ljava/util/concurrent/Executor;

    new-instance v1, Landroidx/appcompat/view/menu/ga1;

    invoke-direct {v1, p0}, Landroidx/appcompat/view/menu/ga1;-><init>(Landroidx/appcompat/view/menu/ia1;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public final synthetic d()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/ia1;->b:Landroidx/appcompat/view/menu/fp;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/fp;->q()Ljava/lang/Iterable;

    move-result-object v0

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/z11;

    iget-object v2, p0, Landroidx/appcompat/view/menu/ia1;->c:Landroidx/appcompat/view/menu/la1;

    const/4 v3, 0x1

    invoke-interface {v2, v1, v3}, Landroidx/appcompat/view/menu/la1;->a(Landroidx/appcompat/view/menu/z11;I)V

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final synthetic e()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/ia1;->d:Landroidx/appcompat/view/menu/ly0;

    new-instance v1, Landroidx/appcompat/view/menu/ha1;

    invoke-direct {v1, p0}, Landroidx/appcompat/view/menu/ha1;-><init>(Landroidx/appcompat/view/menu/ia1;)V

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/ly0;->d(Landroidx/appcompat/view/menu/ly0$a;)Ljava/lang/Object;

    return-void
.end method
