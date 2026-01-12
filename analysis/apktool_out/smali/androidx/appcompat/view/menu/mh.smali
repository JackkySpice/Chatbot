.class public abstract Landroidx/appcompat/view/menu/mh;
.super Landroidx/appcompat/view/menu/h;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/zg;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/mh$a;
    }
.end annotation


# static fields
.field public static final n:Landroidx/appcompat/view/menu/mh$a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/mh$a;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/mh$a;-><init>(Landroidx/appcompat/view/menu/kj;)V

    sput-object v0, Landroidx/appcompat/view/menu/mh;->n:Landroidx/appcompat/view/menu/mh$a;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/zg;->b:Landroidx/appcompat/view/menu/zg$b;

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/h;-><init>(Landroidx/appcompat/view/menu/jh$c;)V

    return-void
.end method


# virtual methods
.method public abstract A(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V
.end method

.method public D(Landroidx/appcompat/view/menu/jh;)Z
    .locals 0

    const/4 p1, 0x1

    return p1
.end method

.method public E(I)Landroidx/appcompat/view/menu/mh;
    .locals 1

    invoke-static {p1}, Landroidx/appcompat/view/menu/b90;->a(I)V

    new-instance v0, Landroidx/appcompat/view/menu/a90;

    invoke-direct {v0, p0, p1}, Landroidx/appcompat/view/menu/a90;-><init>(Landroidx/appcompat/view/menu/mh;I)V

    return-object v0
.end method

.method public d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;
    .locals 0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/zg$a;->a(Landroidx/appcompat/view/menu/zg;Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object p1

    return-object p1
.end method

.method public j(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh;
    .locals 0

    invoke-static {p0, p1}, Landroidx/appcompat/view/menu/zg$a;->b(Landroidx/appcompat/view/menu/zg;Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    return-object p1
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-static {p0}, Landroidx/appcompat/view/menu/gj;->a(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x40

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {p0}, Landroidx/appcompat/view/menu/gj;->b(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final x(Landroidx/appcompat/view/menu/wg;)V
    .locals 1

    const-string v0, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<*>"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->c(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Landroidx/appcompat/view/menu/am;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/am;->q()V

    return-void
.end method

.method public final z(Landroidx/appcompat/view/menu/wg;)Landroidx/appcompat/view/menu/wg;
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/am;

    invoke-direct {v0, p0, p1}, Landroidx/appcompat/view/menu/am;-><init>(Landroidx/appcompat/view/menu/mh;Landroidx/appcompat/view/menu/wg;)V

    return-object v0
.end method
