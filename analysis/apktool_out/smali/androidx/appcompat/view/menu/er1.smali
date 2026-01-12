.class public final Landroidx/appcompat/view/menu/er1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ig0;
.implements Landroidx/appcompat/view/menu/eg0;
.implements Landroidx/appcompat/view/menu/bg0;
.implements Landroidx/appcompat/view/menu/nd2;


# instance fields
.field public final a:Ljava/util/concurrent/Executor;

.field public final b:Landroidx/appcompat/view/menu/xg;

.field public final c:Landroidx/appcompat/view/menu/jf2;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/xg;Landroidx/appcompat/view/menu/jf2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/er1;->a:Ljava/util/concurrent/Executor;

    iput-object p2, p0, Landroidx/appcompat/view/menu/er1;->b:Landroidx/appcompat/view/menu/xg;

    iput-object p3, p0, Landroidx/appcompat/view/menu/er1;->c:Landroidx/appcompat/view/menu/jf2;

    return-void
.end method

.method public static bridge synthetic e(Landroidx/appcompat/view/menu/er1;)Landroidx/appcompat/view/menu/xg;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/er1;->b:Landroidx/appcompat/view/menu/xg;

    return-object p0
.end method

.method public static bridge synthetic f(Landroidx/appcompat/view/menu/er1;)Landroidx/appcompat/view/menu/jf2;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/er1;->c:Landroidx/appcompat/view/menu/jf2;

    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/er1;->c:Landroidx/appcompat/view/menu/jf2;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/jf2;->p(Ljava/lang/Object;)V

    return-void
.end method

.method public final b(Landroidx/appcompat/view/menu/vy0;)V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/er1;->a:Ljava/util/concurrent/Executor;

    new-instance v1, Landroidx/appcompat/view/menu/zo1;

    invoke-direct {v1, p0, p1}, Landroidx/appcompat/view/menu/zo1;-><init>(Landroidx/appcompat/view/menu/er1;Landroidx/appcompat/view/menu/vy0;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public final c()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/er1;->c:Landroidx/appcompat/view/menu/jf2;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/jf2;->q()Z

    return-void
.end method

.method public final d(Ljava/lang/Exception;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/er1;->c:Landroidx/appcompat/view/menu/jf2;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/jf2;->o(Ljava/lang/Exception;)V

    return-void
.end method
