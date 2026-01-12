.class public final Landroidx/appcompat/view/menu/g5$c;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/pf0;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/g5;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "c"
.end annotation


# static fields
.field public static final a:Landroidx/appcompat/view/menu/g5$c;

.field public static final b:Landroidx/appcompat/view/menu/mr;

.field public static final c:Landroidx/appcompat/view/menu/mr;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/g5$c;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/g5$c;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/g5$c;->a:Landroidx/appcompat/view/menu/g5$c;

    const-string v0, "clientType"

    invoke-static {v0}, Landroidx/appcompat/view/menu/mr;->d(Ljava/lang/String;)Landroidx/appcompat/view/menu/mr;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/g5$c;->b:Landroidx/appcompat/view/menu/mr;

    const-string v0, "androidClientInfo"

    invoke-static {v0}, Landroidx/appcompat/view/menu/mr;->d(Ljava/lang/String;)Landroidx/appcompat/view/menu/mr;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/g5$c;->c:Landroidx/appcompat/view/menu/mr;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public bridge synthetic a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/xb;

    check-cast p2, Landroidx/appcompat/view/menu/qf0;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/g5$c;->b(Landroidx/appcompat/view/menu/xb;Landroidx/appcompat/view/menu/qf0;)V

    return-void
.end method

.method public b(Landroidx/appcompat/view/menu/xb;Landroidx/appcompat/view/menu/qf0;)V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/g5$c;->b:Landroidx/appcompat/view/menu/mr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/xb;->c()Landroidx/appcompat/view/menu/xb$b;

    move-result-object v1

    invoke-interface {p2, v0, v1}, Landroidx/appcompat/view/menu/qf0;->e(Landroidx/appcompat/view/menu/mr;Ljava/lang/Object;)Landroidx/appcompat/view/menu/qf0;

    sget-object v0, Landroidx/appcompat/view/menu/g5$c;->c:Landroidx/appcompat/view/menu/mr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/xb;->b()Landroidx/appcompat/view/menu/b2;

    move-result-object p1

    invoke-interface {p2, v0, p1}, Landroidx/appcompat/view/menu/qf0;->e(Landroidx/appcompat/view/menu/mr;Ljava/lang/Object;)Landroidx/appcompat/view/menu/qf0;

    return-void
.end method
