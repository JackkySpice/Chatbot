.class public final Landroidx/appcompat/view/menu/d81;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/c81;


# instance fields
.field public final b:Landroidx/appcompat/view/menu/c81;

.field public final c:Landroidx/appcompat/view/menu/m9;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/c81;)V
    .locals 1

    const-string v0, "tracker"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Landroidx/appcompat/view/menu/m9;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/m9;-><init>()V

    invoke-direct {p0, p1, v0}, Landroidx/appcompat/view/menu/d81;-><init>(Landroidx/appcompat/view/menu/c81;Landroidx/appcompat/view/menu/m9;)V

    return-void
.end method

.method public constructor <init>(Landroidx/appcompat/view/menu/c81;Landroidx/appcompat/view/menu/m9;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/d81;->b:Landroidx/appcompat/view/menu/c81;

    iput-object p2, p0, Landroidx/appcompat/view/menu/d81;->c:Landroidx/appcompat/view/menu/m9;

    return-void
.end method


# virtual methods
.method public a(Landroid/app/Activity;)Landroidx/appcompat/view/menu/ws;
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/d81;->b:Landroidx/appcompat/view/menu/c81;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/c81;->a(Landroid/app/Activity;)Landroidx/appcompat/view/menu/ws;

    move-result-object p1

    return-object p1
.end method

.method public final b(Landroid/app/Activity;Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/of;)V
    .locals 2

    const-string v0, "activity"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "executor"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "consumer"

    invoke-static {p3, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/d81;->c:Landroidx/appcompat/view/menu/m9;

    iget-object v1, p0, Landroidx/appcompat/view/menu/d81;->b:Landroidx/appcompat/view/menu/c81;

    invoke-interface {v1, p1}, Landroidx/appcompat/view/menu/c81;->a(Landroid/app/Activity;)Landroidx/appcompat/view/menu/ws;

    move-result-object p1

    invoke-virtual {v0, p2, p3, p1}, Landroidx/appcompat/view/menu/m9;->a(Ljava/util/concurrent/Executor;Landroidx/appcompat/view/menu/of;Landroidx/appcompat/view/menu/ws;)V

    return-void
.end method

.method public final c(Landroidx/appcompat/view/menu/of;)V
    .locals 1

    const-string v0, "consumer"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/d81;->c:Landroidx/appcompat/view/menu/m9;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/m9;->b(Landroidx/appcompat/view/menu/of;)V

    return-void
.end method
